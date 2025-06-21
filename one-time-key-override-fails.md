# `derivepassphrase` bug one-time-key-override-fails

???+ bug-success "Bug details: `derivepassphrase -k` fails when overriding the chosen key on the command-line"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/d000e7cbd2cfdfd86f614a9f65acea039baeff70">d000e7cbd2cfdfd86f614a9f65acea039baeff70</a> (0.1.3)
    </table>

````console-session
$ mkdir -p ~/.derivepassphrase
$ derivepassphrase -k --config
Suitable SSH keys:
[1] ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjuC9...
[2] ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/RzZ...
Your selection? (1-2, leave empty to abort): 1
$ derivepassphrase -k -l 35 abc
Suitable SSH keys:
[1] ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjuC9...
[2] ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/RzZ...
Your selection? (1-2, leave empty to abort): 2
Traceback (most recent call last):
  File ".../derivepassphrase", line 8, in <module>
    sys.exit(derivepassphrase())
             ^^^^^^^^^^^^^^^^^^
  File ".../click/core.py", line 1157, in __call__
    return self.main(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File ".../click/core.py", line 1078, in main
    rv = self.invoke(ctx)
         ^^^^^^^^^^^^^^^^
  File ".../click/core.py", line 1434, in invoke
    return ctx.invoke(self.callback, **ctx.params)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File ".../click/core.py", line 783, in invoke
    return __callback(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File ".../click/decorators.py", line 33, in new_func
    return f(get_current_context(), *args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File ".../derivepassphrase/cli.py", line 1077, in derivepassphrase
    vault = dpp.Vault(**kwargs)
            ^^^^^^^^^^^^^^^^^^^
TypeError: Vault.__init__() got an unexpected keyword argument 'key'
````

It works for stored settings, though.

--------

Actually, this concrete error requires a selected key in the settings, and a `-k` argument on the command-line. It is not triggered by a naïve call of `derivepassphrase -k`.
