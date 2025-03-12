# `derivepassphrase` bug remove-pageant-build-info-check

???+ success "Bug details: Remove Pageant build info check"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2><b>0.2.0</b> 0.3.0 0.3.1 0.3.2 0.3.3
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/e97b966ecba87289b839e0fbac736f0b53782ed5">e97b966ecba87289b839e0fbac736f0b53782ed5</a> (0.4.0)
    </table>

In [test-suite-isolated-ssh-agent](test-suite-isolated-ssh-agent.md), we encountered a bug in Pageant where the agent socket becomes undiscoverable if Pageant is spawned as a subprocess, in debug mode.  We wrote and submitted a patch to upstream PuTTY, which will hopefully make it into PuTTY 0.82.  [63b51df7a39fd642ca079ac390014d23f617b972](https://github.com/the-13th-letter/derivepassphrase/commit/63b51df7a39fd642ca079ac390014d23f617b972) introduced a check for a fixed version of Pageant by asserting a version number 0.82 or greater, or by the presence of a specific build identifier.  This check further enables running Pageant in foreground mode, which is a small feature request related to and submitted together with the patch above.

Of course, this version check in its current form is only a temporary measure, and there is no guarantee that 0.82 will be the first version where the bug is fixed or the foreground mode feature is implemented, if at all.  The local build identifier check furthermore assumes that Pageant's version number adheres to [PEP 440](https://peps.python.org/pep-0440/), which is not guaranteed by upstream PuTTY, neither in format nor in semantics.

<b>Therefore</b>, once a fixed version of PuTTY has been released, remove the build identifier checks and update the minimum required version to whatever version number the fixed PuTTY version has.  If necessary, adapt the version comparison code as well.

--------

> In [test-suite-isolated-ssh-agent](test-suite-isolated-ssh-agent.md), we encountered a bug in Pageant where the agent socket becomes undiscoverable if Pageant is spawned as a subprocess, in debug mode. We wrote and submitted a patch to upstream PuTTY, which will hopefully make it into PuTTY 0.82. [63b51df](https://github.com/the-13th-letter/derivepassphrase/commit/63b51df7a39fd642ca079ac390014d23f617b972) introduced a check for a fixed version of Pageant by asserting a version number 0.82 or greater, or by the presence of a specific build identifier. This check further enables running Pageant in foreground mode, which is a small feature request related to and submitted together with the patch above.

The "undiscoverable socket in debug mode" bug has been fixed upstream in [fca6ce10dbf01e57ec4777b87faae8b38e53ff43](https://git.tartarus.org/?p=simon/putty.git;a=commit;h=fca6ce10dbf01e57ec4777b87faae8b38e53ff43), and foreground mode has been introduced in [2b93417398f641e410f0b3564135508ebfb71ac0](https://git.tartarus.org/?p=simon/putty.git;a=commit;h=2b93417398f641e410f0b3564135508ebfb71ac0). Both commits should be included in PuTTY 0.82.
