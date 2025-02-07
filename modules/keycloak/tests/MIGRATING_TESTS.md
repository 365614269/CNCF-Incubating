### Basics

When migrating tests use the remote server mode as this will make it much quicker to run tests than having to start/stop
Keycloak when you run the test from the IDE.

Add `@KeycloakIntegrationTest` to the class.

Change `import org.junit.Test;` to `import org.junit.jupiter.api.Test;`

Remove extends `AbstractKeycloakTest` as the new test framework provides injection of resources needed by the test there
is no need for the `AbstractKeycloakTest` and tests should instead inject what they need.

One thing your test is most likely going to need is a realm, this is now done with:

```
@InjectRealm
ManagedRealm realm;
```

### Changed packages/classes

| Old                                         | New                                            |
|---------------------------------------------|------------------------------------------------|
| org.junit.Assert                            | org.junit.jupiter.api.Assertions               |
| org.junit.Test                              | org.junit.jupiter.api.Test                     |
| org.keycloak.testsuite.admin.ApiUtil        | org.keycloak.tests.utils.admin.ApiUtil         |
| org.keycloak.testsuite.util.AdminEventPaths | org.keycloak.tests.utils.admin.AdminEventPaths |

### Assertions

Change `import org.junit.Assert;` to `import org.junit.jupiter.api.Assertions;`, and replace `Assert.` with `Assertions.` throughout.

If the assert passes a message (for example `Assert.assertEquals("Message", expected, actual)`) the message in `Assertions`
is now the last parameter (for example `Assertions.assertEquals(expected, actual, "Message")`).

### Admin events

Admin events are handled slightly differently in the new test framework.

An example for the old testsuite:

```
@Rule
public AssertAdminEvents assertAdminEvents = new AssertAdminEvents(this);

public void myTest() {
    assertAdminEvents.assertEvent(realmId, OperationType.CREATE, ...);
}
```

Converted to the new test framework:

```
@InjectAdminEvents
public AdminEvents adminEvents;

public void myTest() {
    AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.CREATE, ...);
}
```

Notice that there is no need to pass `realmId` when asserting an event, that is because the `AdminEvents` will only
receive events for the current realm.

For better readability `AdminEventAssertion` provides a method chaining approach to assert various fields in the event 
(the example above could be change to `AdminEventAssertion.assertSuccess(adminEvents.poll()).operationType(OperationType.CREATE)...`).

There is also improved support for skipping events using skip methods, that allows skipping one event (`.skip()`), 
multiple events (`.skip(5)`), or skipping all previous events (`.skipAll()`).