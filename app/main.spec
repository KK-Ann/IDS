# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
import os

# 保证路径写法适配所有平台
project_root = os.path.abspath('.')

# 添加所需的资源文件夹
datas = [
    (os.path.join(project_root, 'templates'), 'templates'),
    (os.path.join(project_root, 'static'), 'static'),
    (os.path.join(project_root, 'model'), 'model')
]

# 自动收集 flask_socketio 和 engineio 的数据文件
datas += collect_data_files('flask_socketio')
datas += collect_data_files('engineio')

a = Analysis(
    ['main.py'],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'engineio.async_drivers.threading',
        'sklearn',
        'sklearn.ensemble._forest',
        'sklearn.preprocessing._data',
        'sklearn.decomposition._pca',
        'sklearn.model_selection._split',
        'sklearn.model_selection._search',
        'sklearn.metrics._classification',
        'sklearn.utils._encode',
        'sklearn.utils._param_validation',
        'sklearn.base',
        'sklearn.pipeline',
        'sklearn.tree',
        'sklearn.utils._pickle',
        'joblib',
        'imblearn',
        'imblearn.over_sampling',
        'imblearn.over_sampling._smote',
        'imblearn.under_sampling',
        'imblearn.under_sampling._prototype_selection'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 改为 True 可显示终端输出（调试用）
    icon='logo.ico',
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
