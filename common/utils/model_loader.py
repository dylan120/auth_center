"""
app models auto load
"""

import importlib
from pathlib import Path

from django.db import models


def auto_discover_models(
    app_name: str, caller_globals: dict, models_subdir: str = "models"
):
    """
    自动扫描指定 app 的 models/ 目录，加载所有继承 django.db.models.Model 的类，
    并注入到调用者的全局命名空间（通常是 models/__init__.py 的 globals()）。

    :param app_name: Django app 的名称（如 'users', 'ads'）
    :param caller_globals: 调用此函数的模块的 globals()，用于注入模型类
    :param models_subdir: 模型目录
    """
    # 构建 models 目录路径：假设结构为 app_name/models/
    try:
        app_module = importlib.import_module(app_name)
        models_dir = Path(app_module.__file__).parent / models_subdir
    except (ImportError, AttributeError) as e:
        raise RuntimeError(f"无法定位 app '{app_name}' 的 models 目录: {e}")

    if not models_dir.exists() or not models_dir.is_dir():
        raise RuntimeError(f"App '{app_name}' 下未找到 models/ 目录")

    loaded_models = set()

    # 遍历 models 目录下所有 .py 文件
    for file_path in models_dir.glob("*.py"):
        if file_path.name == "__init__.py":
            continue

        module_name = file_path.stem
        full_module_name = f"{app_name}.models.{module_name}"

        try:
            module = importlib.import_module(full_module_name)

            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue

                attr = getattr(module, attr_name)
                if _is_concrete_django_model(attr):
                    model_key = f"{attr.__module__}.{attr.__name__}"
                    if model_key in loaded_models:
                        continue
                    loaded_models.add(model_key)
                    # 注入到调用者的命名空间（如 models/__init__.py）
                    caller_globals[attr_name] = attr

        except Exception as e:
            # 开发阶段可 raise，生产环境建议记录日志
            raise RuntimeError(f"加载模型模块 {full_module_name} 失败: {e}") from e


def _is_concrete_django_model(obj):
    """判断是否为可迁移的具体 Django 模型"""
    return (
        isinstance(obj, type)
        and issubclass(obj, models.Model)
        and hasattr(obj, "_meta")
        and not obj._meta.abstract
        and not getattr(obj._meta, "proxy", False)
    )
