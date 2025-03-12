# `derivepassphrase` wish test-suite-isolated-ssh-agent

???+ success "Wish details: Support and isolate OpenSSH&apos;s `ssh-agent` and PuTTY&apos;s `pageant` in the test suite"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.1.3 <b>0.2.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/dd606b3a051f0ba3bc76d0ef6e14ba3fb5d87298">dd606b3a051f0ba3bc76d0ef6e14ba3fb5d87298</a> (0.3.0)
    </table>

When testing SSH agent-related functionality, currently the test suite will use whatever agent happens to be running (if any), and upload test keys to and issue test queries against said agent.  The test keys are re-uploaded in every test that uses them, with a fixed lifetime of 30 seconds.

Of course, this setup muddles the agent's supported key list.  In extreme cases, it could even lead to legitimate SSH connections failing to authenticate because an OpenSSH client (with `IdentitiesOnly` off) naively tries out all of our test keys against a server, exhausting its number of authentication attempts.

Additionally, this setup does not work for PuTTY's Pageant, because [Pageant does not support key lifetimes/timeouts](https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-timeout.html).  Furthermore, because key lifetime constraints are part of the core agent protocol, instead of a protocol extension, we cannot reliably query the support status of this feature.

<b>Therefore</b>, instead of the test suite expecting to run alongside an already-running SSH agent, attempt to spawn one ourselves: try OpenSSH first, then PuTTY, else fall back (as before) to a running SSH agent, if any.

(As an added bonus, if the agent is under our control, then we don't have to control the lifetime of the keys for isolation purposes anymore.   So Pageant's lack of support for this setting is then irrelevant.)

Because of the standard calling conventions of both `ssh-agent` and `pageant`, if actually spawned by us, then we will be running the respective agent in the foreground, and have to do the necessary environment manipulation (`SSH_AUTH_SOCK` variable) ourselves.  We will then also need to ensure the agent is terminated when the test suite exits.

--------

> Therefore, instead of the test suite expecting to run alongside an already-running SSH agent, attempt to spawn one ourselves: try OpenSSH first, then PuTTY, else fall back (as before) to a running SSH agent, if any.

I have since changed this approach for test coverage reasons.  Because there are only two agent implementations and rather few affected tests, it is still viable to attempt to test every combination.  A new pytest fixture `running_ssh_agent` loops through the known agent configurations and ensures that *some* agent is running, otherwise it skips the running test.  Another new parametrized pytest fixture `ssh_agent_client_with_test_keys_loaded` spawns a client for every known agent configuration and preloads all standard test keys, skipping only if the agent or the client didn't spawn or if all test keys failed to load in the agent.

For PuTTY, this currently requires a patched Pageant version; see next point.

> Because of the standard calling conventions of both `ssh-agent` and `pageant`, if actually spawned by us, then we will be running the respective agent in the foreground, and have to do the necessary environment manipulation (`SSH_AUTH_SOCK` variable) ourselves. We will then also need to ensure the agent is terminated when the test suite exits.

As of version 0.81, Pageant has a problem with output buffering when run in debug mode, its standard foreground mode: to communicate with the test harness, Pageant's standard output is a pipe, which means the C `stdio` library uses fully buffered output by default.  Pageant therefore writes its `SSH_AUTH_SOCK` line to the buffer.  In general, the buffer isn't filled by this, so the `SSH_AUTH_SOCK` line doesn't flush to standard output yet. This is a deadlock: clients are waiting for Pageant to report its socket address so they can connect, and Pageant is waiting for connections to have something to report about.

As a workaround, it is of course possible to run Pageant in one of its forking modes and track the PID of that instance directly, but this is inherently susceptible to race conditions because the PID might get silently reused, and it lacks a cross-platform Python API.

A bug report and a patch has been submitted to PuTTY on 2024-09-18, and reception acknowledged on 2024-09-22.  A locally patched version with proper output flushing has been tested, and behaves very well in this usage.

--------

> As of version 0.81, Pageant has a problem with output buffering when run in debug mode, its standard foreground mode: to communicate with the test harness, Pageant's standard output is a pipe, which means the C `stdio` library uses fully buffered output by default. Pageant therefore writes its `SSH_AUTH_SOCK` line to the buffer. In general, the buffer isn't filled by this, so the `SSH_AUTH_SOCK` line doesn't flush to standard output yet. This is a deadlock: clients are waiting for Pageant to report its socket address so they can connect, and Pageant is waiting for connections to have something to report about.
> 
> […]
> 
> A bug report and a patch has been submitted to PuTTY on 2024-09-18, and reception acknowledged on 2024-09-22. A locally patched version with proper output flushing has been tested, and behaves very well in this usage.

[The aforementioned patch has been added to PuTTY/Pageant](https://git.tartarus.org/?p=simon/putty.git;a=commit;h=fca6ce10dbf01e57ec4777b87faae8b38e53ff43), and will likely be part of PuTTY 0.82.

Simon Tatham, PuTTY's principal author, has further clarified that he considers `derivepassphrase`'s handling to be an abuse of Pageant's debug mode, which was never intended to be machine-parsable. He is instead in favor of the new foreground mode for Pageant (as alluded to in https://github.com/the-13th-letter/derivepassphrase/issues/14#issue-2541165526) which is also due to become part of PuTTY 0.82.
