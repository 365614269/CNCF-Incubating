<#import "/templates/guide.adoc" as tmpl>
<#import "/templates/kc.adoc" as kc>
<#import "/templates/links.adoc" as links>

<@tmpl.guide
title="Transient users for brokering support [experimental]"
summary="How to configure Keycloak server to not store users from identity providers in the database."
includedOptions="">

When using Keycloak as an identity broker, you can configure the Keycloak server
to not create users in its local database when a user authenticates with an external
identity provider. This user is called a _transient user_. Transient users are only
stored within a specific user session and they cease to exist once that session is removed.

== Configuring the transient users for a identity provider

In order to use transient users, you need to enable them in the Keycloak
server first by enabling `transient-users` feature.

<@kc.start parameters="--features=transient-users"/>

Once the feature is enabled, you can configure the identity provider to use transient users
by enabling the `Do Not Store Users` option in the respective identity provider configuration.

== Considerations

When using transient users, you should be aware of the following:

- In the Admin Console, transitive users can be only tracked from their
  respective client session. They cannot be looked up using
  the Users search because they are not stored
  in any user store. For the same reason, it is not possible to add additional
  authentication factors to them.

- Roles and groups can be assigned to the transient users only by
  identity provider mappers of the respective identity provider.

- Since every transient user is created afresh, mappers always
  work in the `Import` sync mode.

- It is possible to leverage offline sessions with transient users.
  To do so, you need to add a role mapper to the identity provider that will assign
  the `offline_access` role to transient users. Beware that the transient user may then
  be stored in the Keycloak database until the respective session expires or the token is revoked.
  Always consider using persistent rather than transient users when offline sessions are
  needed since persistent users can manage offline tokens more easily
  by the Account Console. Also, the transient users feature contributes
  the purpose of not storing any personally identifiable information into the database.
  Since offline sessions are persisted in database, the transient user data would be stored
  there as well. It is up to the administrator to determine whether this is acceptable or not.

- Technically, transient user data is stored as part
  of the user session. It thus increases the session size.

</@tmpl.guide>