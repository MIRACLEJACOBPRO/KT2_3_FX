#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据处理模块 - 风险路径识别系统

该模块负责处理原始日志数据，识别攻击行为，并提取关键信息。
"""

import json
import os
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义常量
TEST_DATA_PATH = os.path.join('all_data', 'test_data', 'test.json')
OUTPUT_DIR = 'output'
PROCESSED_DATA_PATH = os.path.join(OUTPUT_DIR, 'processed_data.json')

# 攻击行为特征
ATTACK_PATTERNS = {
    # 认证失败
    'AUTH_FAILURE': {'weight': 0.7},
    # 敏感文件访问
    'FILE_READ': {'sensitive_paths': ['/etc/passwd', '/etc/shadow', '/etc/arm/credentials.dat', 
                                     '/etc/vehicle/auth_keys.dat', '/etc/arm/config.ini'],
                 'weight': 0.8},
    # 可疑进程启动
    'PROCESS_LAUNCH': {'suspicious_cmds': ['tcpdump', 'nmap', 'ssh-keygen', 'scp', 'rm -f /var/log'],
                      'weight': 0.6},
    # 文件删除
    'FILE_DELETE': {'sensitive_paths': ['/var/log/auth.log', '/var/log/system.log'],
                   'weight': 0.9},
    # 可疑网络连接
    'NETWORK_CONNECTION': {'weight': 0.5},
    # 可疑网络接收
    'NETWORK_RECEIVE': {'weight': 0.4}
}

class LogEvent:
    """日志事件类，表示单个日志事件"""
    
    def __init__(self, event_data):
        self.timestamp = event_data.get('timestamp')
        self.type = event_data.get('type')
        self.subject = event_data.get('subject', {})
        self.object = event_data.get('object', {})
        self.properties = event_data.get('properties', {})
        self.attack_score = 0.0  # 攻击行为评分
        self.is_attack = False   # 是否为攻击行为
        
    def to_dict(self):
        """将事件转换为字典格式"""
        return {
            'timestamp': self.timestamp,
            'type': self.type,
            'subject': self.subject,
            'object': self.object,
            'properties': self.properties,
            'attack_score': self.attack_score,
            'is_attack': self.is_attack
        }
    
    def __str__(self):
        return f"Event[{self.timestamp}] {self.type} - {self.subject.get('host', 'unknown')} - Score: {self.attack_score}"


class DataProcessor:
    """数据处理器，负责处理日志数据和识别攻击行为"""
    
    def __init__(self, data_path=TEST_DATA_PATH):
        self.data_path = data_path
        self.events = []
        self.attack_events = []
        
    def load_data(self):
        """加载测试数据"""
        try:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
                
            logger.info(f"成功加载数据，共 {len(raw_data)} 条记录")
            return raw_data
        except Exception as e:
            logger.error(f"加载数据失败: {str(e)}")
            return []
    
    def parse_events(self, raw_data):
        """解析日志事件数据"""
        self.events = [LogEvent(event) for event in raw_data]
        logger.info(f"成功解析 {len(self.events)} 条事件")
        
    def sort_events_by_time(self):
        """按时间顺序排序日志事件"""
        self.events.sort(key=lambda x: datetime.fromisoformat(x.timestamp))
        logger.info("事件已按时间顺序排序")
        
    def identify_attack_events(self):
        """识别攻击行为"""
        logger.info("开始识别攻击行为...")
        
        for event in self.events:
            # 计算攻击评分
            score = self._calculate_attack_score(event)
            event.attack_score = score
            
            # 评分超过阈值，标记为攻击行为
            if score >= 0.6:
                event.is_attack = True
                self.attack_events.append(event)
                
        logger.info(f"已识别到攻击行为: {len(self.attack_events)} 条")
        
    def _calculate_attack_score(self, event):
        """计算攻击评分"""
        score = 0.0
        event_type = event.type
        
        # 认证失败
        if event_type == 'AUTH_FAILURE':
            score += ATTACK_PATTERNS['AUTH_FAILURE']['weight']
            
        # 敏感文件访问
        elif event_type == 'FILE_READ':
            file_path = event.object.get('path', '')
            sensitive_paths = ATTACK_PATTERNS['FILE_READ']['sensitive_paths']
            if any(path in file_path for path in sensitive_paths):
                score += ATTACK_PATTERNS['FILE_READ']['weight']
                
        # 可疑进程启动
        elif event_type == 'PROCESS_LAUNCH':
            cmd = event.properties.get('command_line', '')
            suspicious_cmds = ATTACK_PATTERNS['PROCESS_LAUNCH']['suspicious_cmds']
            if any(cmd_pattern in cmd for cmd_pattern in suspicious_cmds):
                score += ATTACK_PATTERNS['PROCESS_LAUNCH']['weight']
                
        # 文件删除
        elif event_type == 'FILE_DELETE':
            file_path = event.object.get('path', '')
            sensitive_paths = ATTACK_PATTERNS['FILE_DELETE']['sensitive_paths']
            if any(path in file_path for path in sensitive_paths):
                score += ATTACK_PATTERNS['FILE_DELETE']['weight']
                
        # 可疑网络连接
        elif event_type == 'NETWORK_CONNECTION':
            dest_ip = event.object.get('ip', '')
            # 外部IP或非本地IP
            if not dest_ip.startswith('192.168.') or dest_ip != event.subject.get('host', ''):
                score += ATTACK_PATTERNS['NETWORK_CONNECTION']['weight']
                
        # 可疑网络接收
        elif event_type == 'NETWORK_RECEIVE':
            data = event.properties.get('data', '')
            # 包含可疑命令的数据
            suspicious_cmds = ATTACK_PATTERNS['PROCESS_LAUNCH']['suspicious_cmds']
            if any(cmd_pattern in data for cmd_pattern in suspicious_cmds):
                score += ATTACK_PATTERNS['NETWORK_RECEIVE']['weight']
                
        return score
    
    def save_processed_data(self):
        """保存处理后的数据"""
        logger.info("保存处理后的数据...")
        
        # 确保输出目录存在
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # 转换事件为字典格式
        events_dict = [event.to_dict() for event in self.events]
        attack_events_dict = [event.to_dict() for event in self.attack_events]
        
        # 构建输出数据
        output_data = {
            'events': events_dict,
            'attack_events': attack_events_dict,
            'total_events': len(self.events),
            'attack_events_count': len(self.attack_events),
            'processed_time': datetime.now().isoformat()
        }
        
        # 保存到文件
        try:
            with open(PROCESSED_DATA_PATH, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"处理后的数据已保存到 {PROCESSED_DATA_PATH}")
            return True
        except Exception as e:
            logger.error(f"保存处理后的数据失败: {str(e)}")
            return False
    
    def run(self):
        """运行数据处理流程"""
        logger.info("开始数据处理流程...")
        
        # 加载数据
        raw_data = self.load_data()
        if not raw_data:
            logger.error("加载数据失败，无法继续处理")
            return False
            
        # 解析事件
        self.parse_events(raw_data)
        
        # 排序事件
        self.sort_events_by_time()
        
        # 识别攻击行为
        self.identify_attack_events()
        
        # 保存处理后的数据
        success = self.save_processed_data()
        
        if success:
            logger.info("数据处理流程完成")
        else:
            logger.error("数据处理流程失败")
            
        return success


if __name__ == "__main__":
    # 创建数据处理器并运行
    processor = DataProcessor()
    processor.run()
