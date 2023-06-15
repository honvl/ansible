def sort_custom(values):
    def custom_sort_key(value):
        if value.startswith(('Gi', 'Te')):
            prefix, rest = value[:2], value[2:]
            return (int(rest.split('/')[0]), prefix, rest.split('/')[1])
        return value
    return sorted(values, key=custom_sort_key)

# The above file should be placed in a directory that is included in the `filter_plugins` configuration in your Ansible playbook.