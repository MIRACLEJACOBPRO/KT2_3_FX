#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
行为链路构建模块 - 风险路径识别系统

该模块负责基于处理后的数据构建完整的行为链路，识别事件之间的因果关系，
构建树形结构表示行为链路，并区分普通行为链路和攻击行为链路。
"""

import json
import os
from datetime import datetime
import logging
from collections import defaultdict

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义常量
PROCESSED_DATA_PATH = os.path.join('output', 'processed_data.json')
OUTPUT_DIR = 'output'
CHAIN_DIR = os.path.join(OUTPUT_DIR, 'chains')
NORMAL_CHAIN_PATH = os.path.join(CHAIN_DIR, 'normal_behavior_chain.txt')
ATTACK_CHAIN_PATH = os.path.join(CHAIN_DIR, 'attack_behavior_chain.txt')
CROSS_DEVICE_ATTACK_CHAIN_PATH = os.path.join(CHAIN_DIR, 'cross_device_attack_chain.txt')

class BehaviorNode:
    """行为节点类，表示行为链路中的一个节点"""
    
    def __init__(self, event, parent=None):
        self.event = event
        self.parent = parent
        self.children = []
        self.depth = 0 if parent is None else parent.depth + 1
        
    def add_child(self, child_node):
        """添加子节点"""
        self.children.append(child_node)
        child_node.parent = self
        
    def to_dict(self):
        """将节点转换为字典格式"""
        return {
            'event': self.event,
            'children': [child.to_dict() for child in self.children]
        }
    
    def __str__(self):
        return f"Node[{self.event['timestamp']}] {self.event['type']} - {self.event['subject'].get('host', 'unknown')}"


class BehaviorChain:
    """行为链路类，表示一系列相关事件组成的链路"""
    
    def __init__(self, root_event=None):
        self.root = BehaviorNode(root_event) if root_event else None
        self.start_time = root_event['timestamp'] if root_event else None
        self.is_attack_chain = False
        self.nodes = {}
        
    def add_event(self, event, parent_id=None):
        """添加事件到链路"""
        node = BehaviorNode(event)
        event_id = self._get_event_id(event)
        self.nodes[event_id] = node
        
        if parent_id and parent_id in self.nodes:
            self.nodes[parent_id].add_child(node)
        elif not self.root:
            self.root = node
            self.start_time = event['timestamp']
            
        # 如果事件是攻击行为，标记整个链路为攻击链路
        if event.get('is_attack', False):
            self.is_attack_chain = True
            
        return node
    
    def _get_event_id(self, event):
        """获取事件的唯一标识符"""
        subject = event.get('subject', {})
        pid = subject.get('pid', 0)
        host = subject.get('host', 'unknown')
        timestamp = event.get('timestamp', '')
        return f"{host}_{pid}_{timestamp}"
    
    def to_dict(self):
        """将链路转换为字典格式"""
        if not self.root:
            return {}
            
        return {
            'start_time': self.start_time,
            'is_attack_chain': self.is_attack_chain,
            'root': self.root.to_dict()
        }
    
    def __str__(self):
        return f"Chain[{self.start_time}] {'Attack' if self.is_attack_chain else 'Normal'}"


class BehaviorChainBuilder:
    """行为链路构建器，负责构建行为链路"""
    
    def __init__(self, data_path=PROCESSED_DATA_PATH):
        self.data_path = data_path
        self.events = []
        self.chains = []
        self.normal_chains = []
        self.attack_chains = []
        self.cross_device_attack_chains = []
        
    def load_data(self):
        """加载处理后的数据"""
        try:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            self.events = data.get('events', [])
            logger.info(f"成功加载数据，共 {len(self.events)} 条事件")
            return True
        except Exception as e:
            logger.error(f"加载数据失败: {str(e)}")
            return False
    
    def build_chains(self):
        """构建行为链路"""
        logger.info("开始构建行为链路...")
        
        # 按主机和进程分组
        host_process_events = defaultdict(list)
        for event in self.events:
            subject = event.get('subject', {})
            host = subject.get('host', 'unknown')
            pid = subject.get('pid', 0)
            key = f"{host}_{pid}"
            host_process_events[key].append(event)
            
        # 为每个主机-进程组构建链路
        for key, events in host_process_events.items():
            # 按时间排序
            events.sort(key=lambda x: datetime.fromisoformat(x['timestamp']))
            
            # 创建链路
            chain = BehaviorChain(events[0])
            parent_id = self._get_event_id(events[0])
            
            for event in events[1:]:
                chain.add_event(event, parent_id)
                parent_id = self._get_event_id(event)
                
            self.chains.append(chain)
            
            # 分类链路
            if chain.is_attack_chain:
                self.attack_chains.append(chain)
            else:
                self.normal_chains.append(chain)
                
        logger.info(f"行为链路构建完成，共 {len(self.chains)} 条链路，其中攻击链路 {len(self.attack_chains)} 条，普通链路 {len(self.normal_chains)} 条")
        
    def _get_event_id(self, event):
        """获取事件的唯一标识符"""
        subject = event.get('subject', {})
        pid = subject.get('pid', 0)
        host = subject.get('host', 'unknown')
        timestamp = event.get('timestamp', '')
        return f"{host}_{pid}_{timestamp}"
    
    def identify_cross_device_chains(self):
        """识别跨设备攻击链路"""
        logger.info("开始识别跨设备攻击链路...")
        
        # 按主机分组攻击事件
        host_attack_events = defaultdict(list)
        for chain in self.attack_chains:
            self._collect_attack_events(chain.root, host_attack_events)
            
        # 识别跨设备攻击模式
        if len(host_attack_events) >= 2:
            # 创建跨设备攻击链路
            cross_device_chain = BehaviorChain()
            cross_device_chain.is_attack_chain = True
            
            # 按时间排序所有攻击事件
            all_attack_events = []
            for host, events in host_attack_events.items():
                all_attack_events.extend(events)
                
            all_attack_events.sort(key=lambda x: datetime.fromisoformat(x['timestamp']))
            
            # 添加事件到跨设备链路
            if all_attack_events:
                cross_device_chain.root = BehaviorNode(all_attack_events[0])
                parent_id = self._get_event_id(all_attack_events[0])
                
                for event in all_attack_events[1:]:
                    cross_device_chain.add_event(event, parent_id)
                    parent_id = self._get_event_id(event)
                    
                self.cross_device_attack_chains.append(cross_device_chain)
                logger.info(f"识别到跨设备攻击链路，涉及 {len(host_attack_events)} 个主机")
        
    def _collect_attack_events(self, node, host_events):
        """收集攻击事件"""
        event = node.event
        if event.get('is_attack', False):
            host = event.get('subject', {}).get('host', 'unknown')
            host_events[host].append(event)
            
        for child in node.children:
            self._collect_attack_events(child, host_events)
    
    def save_chains(self):
        """保存行为链路"""
        logger.info("保存行为链路...")
        
        # 确保输出目录存在
        os.makedirs(CHAIN_DIR, exist_ok=True)
        
        # 保存普通行为链路
        try:
            with open(NORMAL_CHAIN_PATH, 'w', encoding='utf-8') as f:
                f.write("# 普通行为链路\n")
                f.write("# 格式: [时间戳] 主机 - 事件类型: 进程 (PID:进程ID) -> 对象路径\n\n")
                
                for chain in self.normal_chains:
                    self._write_chain_events(f, chain.root)
                    
            logger.info(f"普通行为链路已保存到 {NORMAL_CHAIN_PATH}")
        except Exception as e:
            logger.error(f"保存普通行为链路失败: {str(e)}")
            
        # 保存攻击行为链路
        try:
            with open(ATTACK_CHAIN_PATH, 'w', encoding='utf-8') as f:
                f.write("# 攻击行为链路\n")
                f.write("# 格式: [时间戳] 主机 - 事件类型: 进程 (PID:进程ID) -> 对象路径\n\n")
                
                for chain in self.attack_chains:
                    self._write_chain_events(f, chain.root)
                    
            logger.info(f"攻击行为链路已保存到 {ATTACK_CHAIN_PATH}")
        except Exception as e:
            logger.error(f"保存攻击行为链路失败: {str(e)}")
            
        # 保存跨设备攻击行为链路
        if self.cross_device_attack_chains:
            try:
                with open(CROSS_DEVICE_ATTACK_CHAIN_PATH, 'w', encoding='utf-8') as f:
                    f.write("# 跨设备攻击行为链路\n")
                    f.write("# 格式: [时间戳] 主机 - 事件类型: 进程 (PID:进程ID) -> 对象路径\n\n")
                    
                    for chain in self.cross_device_attack_chains:
                        self._write_chain_events(f, chain.root)
                        
                logger.info(f"跨设备攻击行为链路已保存到 {CROSS_DEVICE_ATTACK_CHAIN_PATH}")
            except Exception as e:
                logger.error(f"保存跨设备攻击行为链路失败: {str(e)}")
    
    def _write_chain_events(self, file, node):
        """将链路事件写入文件"""
        if not node:
            return
            
        event = node.event
        timestamp = event.get('timestamp', '')
        event_type = event.get('type', '')
        subject = event.get('subject', {})
        host = subject.get('host', 'unknown')
        process = subject.get('process', 'unknown')
        pid = subject.get('pid', 0)
        object_path = event.get('object', {}).get('path', 'unknown')
        
        file.write(f"[{timestamp}] {host} - {event_type}: {process} (PID:{pid}) -> {object_path}\n")
        
        for child in node.children:
            self._write_chain_events(file, child)
    
    def run(self):
        """运行行为链路构建流程"""
        logger.info("开始行为链路构建流程...")
        
        # 加载数据
        if not self.load_data():
            logger.error("加载数据失败，无法继续构建行为链路")
            return False
            
        # 构建链路
        self.build_chains()
        
        # 识别跨设备链路
        self.identify_cross_device_chains()
        
        # 保存链路
        self.save_chains()
        
        logger.info("行为链路构建流程完成")
        return True


if __name__ == "__main__":
    # 创建行为链路构建器并运行
    builder = BehaviorChainBuilder()
    builder.run()
