# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#
from c7n_openstack.query import QueryResourceManager, TypeInfo
from c7n_openstack.provider import resources
from c7n.utils import local_session
from c7n.utils import type_schema
from c7n.filters import Filter


@resources.register('user')
class User(QueryResourceManager):
    class resource_type(TypeInfo):
        enum_spec = ('list_users', None)
        id = 'id'
        name = 'name'
        default_report_fields = ['id', 'name', 'enabled', 'description']


@User.filter_registry.register('role')
class RoleFilter(Filter):
    """Filters Users based on their role

    :example:

    .. code-block:: yaml

            policies:
              - name: demo
                resource: openstack.user
                filters:
                  - type: role
                    role_name: admin
                    system_scope: true
    """
    schema = type_schema(
        'role',
        role_name={'type': 'string'},
        role_id={'type': 'string'},
        project_name={'type': 'string'},
        project_id={'type': 'string'},
        system_scope={'type': 'boolean'},
    )

    def user_match_role(self, assignments, user_id,
                        role_id, project_id, system_scope):
        for p in assignments:
            if user_id and p.get('user', '') != user_id:
                continue
            if system_scope and p.get('project'):
                continue
            if project_id and p.get('project', '') != project_id:
                continue
            if role_id and p.id != role_id:
                continue
            return True
        return False

    def process(self, resources, event=None):
        results = []
        openstack = local_session(self.manager.session_factory).client()
        role_name = self.data.get('role_name', None)
        role_id = self.data.get('role_id', None)
        project_name = self.data.get('project_name', None)
        project_id = self.data.get('project_id', None)
        system_scope = self.data.get('system_scope', False)
        if not role_id and role_name:
            role = openstack.get_role(role_name)
            if role:
                role_id = role.id
            else:
                raise ValueError(f"Role {role_name} doesn't exists")
        if not project_id and project_name:
            project = openstack.get_project(project_name)
            if project:
                project_id = project.id
            else:
                raise ValueError(f"Project {project_name} doesn't exists")
        assignments = openstack.list_role_assignments()
        for user in resources:
            user_id = user.id
            if self.user_match_role(assignments, user_id, role_id,
                                    project_id, system_scope):
                results.append(user)
        return results
