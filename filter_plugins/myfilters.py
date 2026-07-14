"""Legacy interface-sorting filters used by network playbooks."""


def sort_custom(values):
    def custom_sort_key(value):
        if value.startswith(("Gi", "Te")):
            prefix, rest = value[:2], value[2:]
            return (int(rest.split("/")[0]), prefix, rest.split("/")[1])
        return value

    return sorted(values, key=custom_sort_key)


class FilterModule(object):
    """Expose this module's custom filters to Ansible."""

    def filters(self):
        return {"sort_custom": sort_custom}
