# `derivepassphrase` bug configuration-directory-must-exist

???+ bug-success "Bug details: `derivepassphrase --config` requires configuration directory to exist"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/a980a643275de28f7715241790f199f947f637f4">a980a643275de28f7715241790f199f947f637f4</a> (0.1.3)
    </table>

````console-session
$ derivepassphrase -k --config
Suitable SSH keys:
[1] ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjuC9...
[2] ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/RzZ...
Your selection? (1-2, leave empty to abort): 1
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
  File ".../derivepassphrase/cli.py", line 1030, in derivepassphrase
    _save_config(configuration)
  File ".../derivepassphrase/cli.py", line 119, in _save_config
    with open(filename, 'w', encoding='UTF-8') as fileobj:
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
FileNotFoundError: [Errno 2] No such file or directory: '.../.derivepassphrase/settings.json'
````

(Also demonstrated in [one-time-key-override-fails](one-time-key-override-fails.md).)

I believe it makes sense to handle `FileNotFoundError` here, but probably no other `OSError` variant, since these are not generally encountered in normal circumstances. I think.
