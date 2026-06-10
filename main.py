#!/usr/bin/env python3
"""CipherBox 密匣 - 本地密码管理器 启动入口"""

import os
import sys

from src.app import main

if __name__ == '__main__':
    # 确保项目根目录在 Python 路径中
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
