"""打包字体资源包（Inter variable）。

承载非 Python 字体资源（Inter-Variable.ttf + LICENSE.txt），经 importlib.resources
读取、font_loader 在启动时注册到 QFontDatabase。需 pyproject ``package-data`` 配置
随包分发——仅声明为包（本 ``__init__.py``）不足以包含非 .py 资源。

Inter（OFL-1.1, (c) Rasmus Andersson）以 variable font 形式分发，单文件覆盖 weight
100-900，Qt6 经 ``QFont.setWeight`` 选择实例，QSS ``font-weight`` 精确生效。
"""
