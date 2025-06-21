# `derivepassphrase` bug better-error-messages

???+ bug-success "Bug details: Improve common error messages in the command-line interface"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b> 0.1.3
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/e662c2e71c50e57f465fdeb8efb403ed77147e8c">e662c2e71c50e57f465fdeb8efb403ed77147e8c</a> (0.2.0)
    </table>

Except for those related to command-line parsing, all error messages in `derivepassphrase` are written to be useful to API users, not command-line end users. Currently, the command-line interface passes those errors through without modification, either via [default behavior of `click`](https://click.palletsprojects.com/en/8.1.x/api/#click.BaseCommand.main "see exception handling, in parameter 'standalone_mode'"), or by explicitly via [`ctx.fail`](https://click.palletsprojects.com/en/8.1.x/api.html#click.Context.fail). At the same time, the API uses standard error types directly if possible, and omits context that is already encoded in the error type. But this context is no longer available on the command-line because only the error message (and not the type) is relayed.

<details class="admonition example">
<summary>Example (trying to set up SSH key use with derivepassphrase)</summary>

````shell-session
$ env -u SSH_AUTH_SOCK derivepassphrase -k --config
Usage: derivepassphrase [OPTIONS] [SERVICE]
Try 'derivepassphrase -h' for help.

Error: 'SSH_AUTH_SOCK environment variable'
````

What's actually happening:

````python
>>> import os
>>> del os.environ['SSH_AUTH_SOCK']
>>> from derivepassphrase.cli import derivepassphrase as main
>>> main.main(args=['-k', '--config'], standalone_mode=False)
Traceback (most recent call last):
  File ".../derivepassphrase/cli.py", line 996, in derivepassphrase
    key = base64.standard_b64encode(_select_ssh_key()).decode(
                                    ^^^^^^^^^^^^^^^^^
  File ".../derivepassphrase/cli.py", line 297, in _select_ssh_key
    suitable_keys = list(_get_suitable_ssh_keys(conn))
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File ".../derivepassphrase/cli.py", line 169, in _get_suitable_ssh_keys
    client = ssh_agent_client.SSHAgentClient(socket=conn)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File ".../ssh_agent_client/__init__.py", line 95, in __init__
    raise KeyError(msg) from None
KeyError: 'SSH_AUTH_SOCK environment variable'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
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
  File ".../derivepassphrase/cli.py", line 1002, in derivepassphrase
    ctx.fail(str(e))
  File ".../click/core.py", line 684, in fail
    raise UsageError(message, self)
click.exceptions.UsageError: 'SSH_AUTH_SOCK environment variable'
````
</details>

I believe the solution is two-fold. First, the API should use proper error subtypes, even if they partially duplicate the error message. Second, the command-line interface should guard all calls into the `derivepassphrase` machinery with proper error checking, and emit more suitable error messages if necessary.
