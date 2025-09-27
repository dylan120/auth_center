# menu = SysMenuResource.objects.get(...)
# perm = SysPermission.objects.create(
#     # ...其他字段,
#     content_type=ContentType.objects.get_for_model(menu),
#     object_id=menu.pk
# )
