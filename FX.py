#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
风险路径识别模块

该模块用于加载行为链路，识别风险路径，计算风险分数，并输出风险路径报告。
"""

import os
import json
import logging
from datetime import datetime
import re

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 定义常量
CHAIN_DIR = os.path.join('output', 'chains')
NORMAL_CHAIN_PATH = os.path.join(CHAIN_DIR, 'normal_behavior_chain.txt')
ATTACK_CHAIN_PATH = os.path.join(CHAIN_DIR, 'attack_behavior_chain.txt')
CROSS_DEVICE_ATTACK_CHAIN_PATH = os.path.join(CHAIN_DIR, 'cross_device_attack_chain.txt')
OUTPUT_DIR = 'output'
RISK_REPORT_PATH = os.path.join(OUTPUT_DIR, 'risk_report.txt')

# 风险评分权重
RISK_WEIGHTS = {
    'AUTH_FAILURE': 5,  # 认证失败
    'FILE_READ': {
        'sensitive': 8,  # 读取敏感文件
        'normal': 1      # 读取普通文件
    },
    'FILE_WRITE': {
        'sensitive': 7,  # 写入敏感文件
        'normal': 1      # 写入普通文件
    },
    'FILE_DELETE': {
        'log': 10,       # 删除日志文件
        'sensitive': 8,  # 删除敏感文件
        'normal': 1      # 删除普通文件
    },
    'PROCESS_LAUNCH': {
        'suspicious': 6,  # 启动可疑进程
        'normal': 1      # 启动普通进程
    },
    'NETWORK_CONNECTION': {
        'external': 7,    # 连接外部网络
        'internal': 3,    # 连接内部网络
        'normal': 1       # 连接普通网络
    },
    'NETWORK_RECEIVE': {
        'suspicious': 6,  # 接收可疑网络数据
        'normal': 1       # 接收普通网络数据
    },
    'USER_LOGIN': {
        'root': 4,        # root用户登录
        'normal': 1       # 普通用户登录
    }
}

# 敏感路径列表
SENSITIVE_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/ssh', 
    '/var/log', '/etc/security', '/root/.ssh',
    '/etc/arm', '/etc/vehicle', '/etc/drone',
    'credentials', 'password', 'auth', 'key', 'config'
]

# 可疑命令列表
SUSPICIOUS_COMMANDS = [
    'rm -rf', 'wget', 'curl', 'nc', 'ncat', 'netcat',
    'chmod 777', 'chmod +x', 'bash -i', 'bash -c',
    'python -c', 'perl -e', 'ruby -e', 'scp', 'sftp',
    'ssh-keygen', 'ssh-keyscan', 'ssh-copy-id'
]

class RiskPath:
    """风险路径类，表示一条风险路径"""
    
    def __init__(self, path_id, events=None, risk_score=0, description=""):
        """初始化风险路径"""
        self.path_id = path_id
        self.events = events or []
        self.risk_score = risk_score
        self.description = description
        self.start_time = None
        self.end_time = None
        self.affected_hosts = set()
        self.affected_processes = set()
        self.attack_techniques = set()
        
    def add_event(self, event):
        """添加事件到风险路径"""
        self.events.append(event)
        
        # 更新开始和结束时间
        event_time = datetime.fromisoformat(event['timestamp'])
        if self.start_time is None or event_time < self.start_time:
            self.start_time = event_time
        if self.end_time is None or event_time > self.end_time:
            self.end_time = event_time
            
        # 更新受影响主机
        host = event['subject'].get('host')
        if host:
            self.affected_hosts.add(host)
            
        # 更新受影响进程
        process = event['subject'].get('process')
        if process:
            self.affected_processes.add(process)
            
        # 更新风险评分
        self.update_risk_score(event)
        
        # 识别攻击技术
        self.identify_attack_technique(event)
        
    def update_risk_score(self, event):
        """更新风险评分"""
        event_type = event['type']
        score = 0
        
        # 基于事件类型的评分
        if event_type == 'AUTH_FAILURE':
            score += RISK_WEIGHTS['AUTH_FAILURE']
            
        elif event_type == 'FILE_READ':
            file_path = event['object'].get('path', '')
            if any(sensitive in file_path.lower() for sensitive in SENSITIVE_PATHS):
                score += RISK_WEIGHTS['FILE_READ']['sensitive']
            else:
                score += RISK_WEIGHTS['FILE_READ']['normal']
                
        elif event_type == 'FILE_WRITE':
            file_path = event['object'].get('path', '')
            if any(sensitive in file_path.lower() for sensitive in SENSITIVE_PATHS):
                score += RISK_WEIGHTS['FILE_WRITE']['sensitive']
            else:
                score += RISK_WEIGHTS['FILE_WRITE']['normal']
                
        elif event_type == 'FILE_DELETE':
            file_path = event['object'].get('path', '')
            if '/var/log' in file_path:
                score += RISK_WEIGHTS['FILE_DELETE']['log']
            elif any(sensitive in file_path.lower() for sensitive in SENSITIVE_PATHS):
                score += RISK_WEIGHTS['FILE_DELETE']['sensitive']
            else:
                score += RISK_WEIGHTS['FILE_DELETE']['normal']
                
        elif event_type == 'PROCESS_LAUNCH':
            cmd = event['properties'].get('command_line', '')
            if any(suspicious in cmd for suspicious in SUSPICIOUS_COMMANDS):
                score += RISK_WEIGHTS['PROCESS_LAUNCH']['suspicious']
            else:
                score += RISK_WEIGHTS['PROCESS_LAUNCH']['normal']
                
        elif event_type == 'NETWORK_CONNECTION':
            dest_ip = event['object'].get('ip', '')
            if not dest_ip.startswith('192.168.'):
                score += RISK_WEIGHTS['NETWORK_CONNECTION']['external']
            elif dest_ip != event['subject'].get('host', ''):
                score += RISK_WEIGHTS['NETWORK_CONNECTION']['internal']
            else:
                score += RISK_WEIGHTS['NETWORK_CONNECTION']['normal']
                
        elif event_type == 'NETWORK_RECEIVE':
            data = event['properties'].get('data', '')
            if any(suspicious in data for suspicious in SUSPICIOUS_COMMANDS):
                score += RISK_WEIGHTS['NETWORK_RECEIVE']['suspicious']
            else:
                score += RISK_WEIGHTS['NETWORK_RECEIVE']['normal']
                
        elif event_type == 'USER_LOGIN':
            user = event['properties'].get('user', '')
            if user == 'root':
                score += RISK_WEIGHTS['USER_LOGIN']['root']
            else:
                score += RISK_WEIGHTS['USER_LOGIN']['normal']
                
        # 更新总分
        self.risk_score += score
        
    def identify_attack_technique(self, event):
        """识别攻击技术"""
        event_type = event['type']
        
        # 凭证破解
        if event_type == 'AUTH_FAILURE':
            self.attack_techniques.add('凭证破解')
            
        # 凭证窃取
        elif event_type == 'FILE_READ':
            file_path = event['object'].get('path', '')
            if any(keyword in file_path.lower() for keyword in ['credentials', 'password', 'auth', 'key']):
                self.attack_techniques.add('凭证窃取')
                
        # 数据窃取
        elif event_type == 'FILE_READ' and 'config' in event['object'].get('path', '').lower():
            self.attack_techniques.add('数据窃取')
            
        # 日志清除
        elif event_type == 'FILE_DELETE' and '/var/log' in event['object'].get('path', ''):
            self.attack_techniques.add('日志清除')
            
        # 横向移动
        elif event_type == 'NETWORK_CONNECTION' and event['object'].get('ip', '') != event['subject'].get('host', ''):
            self.attack_techniques.add('横向移动')
            
        # 命令执行
        elif event_type == 'PROCESS_LAUNCH':
            cmd = event['properties'].get('command_line', '')
            if any(suspicious in cmd for suspicious in ['bash -i', 'bash -c', 'python -c', 'perl -e', 'ruby -e']):
                self.attack_techniques.add('命令执行')
                
    def get_duration(self):
        """获取风险路径持续时间（秒）"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0
        
    def to_dict(self):
        """将风险路径转换为字典格式"""
        return {
            'path_id': self.path_id,
            'risk_score': self.risk_score,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'affected_hosts': list(self.affected_hosts),
            'affected_processes': list(self.affected_processes),
            'attack_techniques': list(self.attack_techniques),
            'events': self.events
        }
        
    def __str__(self):
        hosts = ', '.join(self.affected_hosts)
        techniques = ', '.join(self.attack_techniques)
        return f"RiskPath[{self.path_id}] Score: {self.risk_score}, Hosts: {hosts}, Techniques: {techniques}"


class RiskPathIdentifier:
    """风险路径识别器，用于识别风险路径并生成报告"""
    
    def __init__(self):
        """初始化风险路径识别器"""
        self.attack_chain = []
        self.cross_device_attack_chain = []
        self.risk_paths = []
        self.next_path_id = 1
        
    def load_chains(self):
        """加载行为链路"""
        # 确保输出目录存在
        os.makedirs(CHAIN_DIR, exist_ok=True)
        
        # 加载攻击行为链路
        try:
            with open(ATTACK_CHAIN_PATH, 'r', encoding='utf-8') as f:
                self.attack_chain = f.readlines()
            logger.info(f"成功加载攻击行为链路，共 {len(self.attack_chain)} 行")
        except Exception as e:
            logger.error(f"加载攻击行为链路失败: {str(e)}")
            self.attack_chain = []
            
        # 加载跨设备攻击行为链路
        try:
            with open(CROSS_DEVICE_ATTACK_CHAIN_PATH, 'r', encoding='utf-8') as f:
                self.cross_device_attack_chain = f.readlines()
            logger.info(f"成功加载跨设备攻击行为链路，共 {len(self.cross_device_attack_chain)} 行")
        except Exception as e:
            logger.error(f"加载跨设备攻击行为链路失败: {str(e)}")
            self.cross_device_attack_chain = []
            
    def process_raw_events(self, raw_events):
        """处理原始事件数据"""
        events = []
        
        for line in raw_events:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # 解析事件数据
            try:
                # 示例格式: [2023-01-01T12:00:00] 192.168.1.100 - AUTH_FAILURE: /usr/sbin/sshd (PID:1234) -> /var/log/auth.log
                match = re.match(r'\[(.*?)\] (.*?) - (.*?): (.*?) \(PID:(\d+)\) -> (.*)', line)
                if match:
                    timestamp, host, event_type, process, pid, object_path = match.groups()
                    
                    event = {
                        'timestamp': timestamp,
                        'type': event_type,
                        'subject': {
                            'host': host,
                            'process': process,
                            'pid': int(pid)
                        },
                        'object': {
                            'path': object_path
                        },
                        'properties': {}
                    }
                    
                    events.append(event)
            except Exception as e:
                logger.warning(f"解析事件失败: {line}, 错误: {str(e)}")
                
        return events
        
    def identify_risk_paths(self):
        """识别风险路径"""
        logger.info("开始识别风险路径...")
        
        # 处理跨设备攻击链路
        cross_device_events = self.process_raw_events(self.cross_device_attack_chain)
        if cross_device_events:
            cross_device_path = RiskPath(self.next_path_id)
            self.next_path_id += 1
            
            for event in cross_device_events:
                cross_device_path.add_event(event)
                
            self.risk_paths.append(cross_device_path)
            logger.info(f"识别到跨设备风险路径: {cross_device_path}")
            
        # 处理单设备攻击链路
        attack_events = self.process_raw_events(self.attack_chain)
        
        # 按主机分组
        host_events = {}
        for event in attack_events:
            host = event['subject']['host']
            if host not in host_events:
                host_events[host] = []
            host_events[host].append(event)
            
        # 为每个主机创建风险路径
        for host, events in host_events.items():
            if events:
                host_path = RiskPath(self.next_path_id)
                self.next_path_id += 1
                
                for event in events:
                    host_path.add_event(event)
                    
                self.risk_paths.append(host_path)
                logger.info(f"识别到主机 {host} 的风险路径: {host_path}")
                
        # 按风险评分排序
        self.risk_paths.sort(key=lambda x: x.risk_score, reverse=True)
        
        logger.info(f"风险路径识别完成，共识别到 {len(self.risk_paths)} 条风险路径")
        
    def generate_report(self):
        """生成风险报告"""
        logger.info("生成风险报告...")
        
        # 确保输出目录存在
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # 生成报告内容
        report = "风险路径识别报告\n"
        report += "====================\n\n"
        report += f"生成时间: {datetime.now().isoformat()}\n\n"
        report += f"识别到的风险路径数量: {len(self.risk_paths)}\n\n"
        
        # 风险路径摘要
        report += "风险路径摘要:\n--------------\n"
        for i, path in enumerate(self.risk_paths, 1):
            hosts = ", ".join(path.affected_hosts)
            report += f"{i}. 风险路径ID: {path.path_id}, 风险评分: {path.risk_score}, 受影响主机: {hosts}\n"
            
        # 风险路径详情
        report += "\n风险路径详情:\n--------------\n"
        
        for path in self.risk_paths:
            report += f"\n风险路径ID: {path.path_id}\n"
            report += f"风险评分: {path.risk_score}\n"
            report += f"开始时间: {path.start_time.isoformat() if path.start_time else 'N/A'}\n"
            report += f"结束时间: {path.end_time.isoformat() if path.end_time else 'N/A'}\n"
            report += f"受影响主机: {', '.join(path.affected_hosts)}\n"
            report += f"攻击技术: {', '.join(path.attack_techniques)}\n\n"
            
            report += "事件序列:\n"
            for i, event in enumerate(path.events, 1):
                timestamp = event['timestamp']
                host = event['subject']['host']
                event_type = event['type']
                process = event['subject']['process']
                pid = event['subject']['pid']
                object_path = event['object']['path']
                
                report += f"  {i}. [{timestamp}] {host} - {event_type}: {process} (PID:{pid}) -> {object_path}\n"
                
            report += "\n" + "-" * 50 + "\n"
            
        # 写入报告文件
        try:
            with open(RISK_REPORT_PATH, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"风险报告已保存到 {RISK_REPORT_PATH}")
        except Exception as e:
            logger.error(f"保存风险报告失败: {str(e)}")
            
        return report
        
    def run(self):
        """运行风险路径识别流程"""
        logger.info("开始风险路径识别流程...")
        
        # 加载行为链路
        self.load_chains()
        
        # 识别风险路径
        self.identify_risk_paths()
        
        # 生成报告
        self.generate_report()
        
        logger.info("风险路径识别流程完成")
        

if __name__ == "__main__":
    # 创建风险路径识别器并运行
    identifier = RiskPathIdentifier()
    identifier.run()
