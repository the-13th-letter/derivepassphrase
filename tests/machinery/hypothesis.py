# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""`hypothesis` testing machinery for the `derivepassphrase` test suite.

This is all the `hypothesis`-specific data and functionality used in the
`derivepassphrase` test suite; this includes custom `hypothesis`
strategies, or state machines, or state machine helper functions, or
functions interacting with the `hypothesis` settings.

All similar-minded code requiring only plain `pytest` lives in [the
`pytest` sibling module][tests.machinery.pytest].

"""

from __future__ import annotations

import copy
import importlib
import importlib.util
import math
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, Callable

import hypothesis
import hypothesis.errors
from _pytest import mark as pytest_mark
from hypothesis import strategies
from typing_extensions import assert_type

from derivepassphrase import _types
from tests import data, machinery

__all__ = ()

if TYPE_CHECKING:
    from typing_extensions import Any, TypeIs


# Hypothesis settings management
# ==============================


def _hypothesis_settings_setup() -> None:
    """
    Ensure sensible hypothesis settings if running under coverage.

    In our tests, the sys.monitoring tracer slows down execution speed
    by a factor of roughly 3, the C tracer by roughly 2.5, and the
    Python tracer by roughly 40.  Ensure that hypothesis default
    timeouts apply relative to this *new* execution speed, not the old
    one.

    In any case, we *also* reduce the state machine step count to 32
    steps per run, because the current state machines defined in the
    tests rather benefit from broad testing rather than deep testing.

    This setup function is idempotent: if it detects that the profiles
    have already been registered, then it silently does nothing.

    """
    try:
        hypothesis.settings.get_profile("intense")
    except hypothesis.errors.InvalidArgument:  # pragma: no cover [external]
        pass
    else:  # pragma: no cover [external]
        return

    settings = hypothesis.settings()
    slowdown: float | None = None
    if (
        importlib.util.find_spec("coverage") is not None
        and settings.deadline is not None
        and settings.deadline.total_seconds() < 1.0
    ):  # pragma: no cover [external]
        ctracer_class = (
            importlib.import_module("coverage.tracer").CTracer
            if importlib.util.find_spec("coverage.tracer") is not None
            else type(None)
        )
        pytracer_class = importlib.import_module("coverage.pytracer").PyTracer
        if (
            getattr(sys, "monitoring", None) is not None
            and sys.monitoring.get_tool(sys.monitoring.COVERAGE_ID)
            == "coverage.py"
        ):
            slowdown = 3.0
        elif (
            trace_func := getattr(sys, "gettrace", lambda: None)()
        ) is not None and isinstance(trace_func, ctracer_class):
            slowdown = 2.5
        elif (
            trace_func is not None
            and hasattr(trace_func, "__self__")
            and isinstance(trace_func.__self__, pytracer_class)
        ):
            slowdown = 8.0
    hypothesis.settings.register_profile(
        "default",
        parent=settings,
        deadline=slowdown * settings.deadline
        if slowdown and settings.deadline is not None
        else settings.deadline,
        stateful_step_count=32,
        suppress_health_check=[hypothesis.HealthCheck.too_slow],
    )
    default_profile = hypothesis.settings.get_profile("default")
    hypothesis.settings.register_profile(
        "regression",
        parent=hypothesis.settings.get_profile("ci"),
        derandomize=True,
        database=None,
        max_examples=3,
        stateful_step_count=3,
        suppress_health_check=[hypothesis.HealthCheck.too_slow],
        phases=[
            hypothesis.Phase.explicit,
            hypothesis.Phase.reuse,
            hypothesis.Phase.generate,
        ],
    )
    hypothesis.settings.register_profile(
        "debug",
        parent=default_profile,
        verbosity=hypothesis.Verbosity.verbose,
    )
    hypothesis.settings.register_profile(
        "debug-regression",
        parent=hypothesis.settings.get_profile("regression"),
        verbosity=hypothesis.Verbosity.verbose,
    )
    hypothesis.settings.register_profile(
        "correctness",
        parent=default_profile,
        derandomize=False,
        max_examples=10 * default_profile.max_examples,
    )


def get_concurrency_step_count(
    settings: hypothesis.settings | None = None,
) -> int:
    """Return the desired step count for concurrency-related tests.

    This is the smaller of the [general concurrency
    limit][tests.machinery.get_concurrency_limit] and the step count
    from the current hypothesis settings.

    Args:
        settings:
            The hypothesis settings for a specific tests.  If not given,
            then the current profile will be queried directly.

    """
    if settings is None:  # pragma: no cover
        settings = hypothesis.settings()
    return min(machinery.get_concurrency_limit(), settings.stateful_step_count)


def get_process_spawning_state_machine_examples_count(
    settings: hypothesis.settings | None = None,
) -> int:
    """Return the examples count for process-spawning state machines.

    That is, return the desired `max_examples` setting for state
    machines that spawn processes as part of their operation.  Since
    Python 3.14, process spawning is no longer cheap by default on *any*
    of the main operating systems (they all default to the "forkserver"
    or "spawn" startup methods), and on The Annoying OS, process
    spawning is inherently expensive.  Therefore, we want to limit the
    examples count by default, and require the user to opt-in to the
    original naive example count explicitly.

    If the "correctness" profile is in effect, or something with even
    higher `max_examples` and `stateful_step_count`, then we return the
    unaltered example count for the *default* profile.  Otherwise, we
    return the square root of the `max_examples` setting (rounded down).
    We *never* return a value below the "regression" profile's example
    count: any lower computed example count is increased to the
    "regression" profile's example count.

    Args:
        settings:
            The hypothesis settings for a specific tests.  If not given,
            then the current profile will be queried directly.

    """
    if settings is None:  # pragma: no cover
        settings = hypothesis.settings()

    # Ensure the "intense" profile exists.
    _hypothesis_settings_setup()

    these_values = (settings.max_examples, settings.stateful_step_count)
    correctness_profile = hypothesis.settings.get_profile("correctness")
    correctness_values = (
        correctness_profile.max_examples,
        correctness_profile.stateful_step_count,
    )
    min_count = hypothesis.settings.get_profile("regression").max_examples
    high_count = hypothesis.settings.get_profile("default").max_examples
    correctness_based_testing = (
        these_values[0] >= correctness_values[0]
        and these_values[1] >= correctness_values[1]
    )
    return max(
        min_count,
        high_count
        if correctness_based_testing
        else math.isqrt(settings.max_examples),
    )


# Hypothesis strategies
# =====================


@strategies.composite
def vault_full_service_config(
    draw: strategies.DrawFn,
) -> _types.VaultConfigServicesSettings:
    """Hypothesis strategy for full vault service configurations.

    Returns a sample configuration with restrictions on length, repeat
    count, and all character classes, while ensuring the settings are
    not obviously unsatisfiable.

    Args:
        draw:
            The `draw` function, as provided for by hypothesis.

    """
    repeat = draw(strategies.integers(min_value=0, max_value=10))
    lower = draw(strategies.integers(min_value=0, max_value=10))
    upper = draw(strategies.integers(min_value=0, max_value=10))
    number = draw(strategies.integers(min_value=0, max_value=10))
    space = draw(strategies.integers(min_value=0, max_value=repeat))
    dash = draw(strategies.integers(min_value=0, max_value=10))
    symbol = draw(strategies.integers(min_value=0, max_value=10))
    length = draw(
        strategies.integers(
            min_value=max(1, lower + upper + number + space + dash + symbol),
            max_value=70,
        )
    )
    hypothesis.assume(lower + upper + number + dash + symbol > 0)
    hypothesis.assume(lower + upper + number + space + symbol > 0)
    hypothesis.assume(repeat >= space)
    return {
        "lower": lower,
        "upper": upper,
        "number": number,
        "space": space,
        "dash": dash,
        "symbol": symbol,
        "repeat": repeat,
        "length": length,
    }


@strategies.composite
def smudged_vault_test_config(
    draw: strategies.DrawFn,
    config: strategies.SearchStrategy[
        data.VaultTestConfig
    ] = strategies.sampled_from(data.TEST_CONFIGS).filter(  # noqa: B008
        data.VaultTestConfig.is_smudgable
    ),
) -> data.VaultTestConfig:
    """Hypothesis strategy to replace falsy values with other falsy values.

    Uses [`_types.js_truthiness`][] internally, which is tested
    separately by
    [`tests.test_derivepassphrase_types.test_heavy_duty.test_js_truthiness`][].

    Args:
        draw:
            The `draw` function, as provided for by hypothesis.
        config:
            A strategy which generates [`data.VaultTestConfig`][]
            objects.

    Returns:
        A new [`data.VaultTestConfig`][] where some falsy values have
        been replaced or added.

    """

    falsy = (None, False, 0, 0.0, "", float("nan"))
    falsy_no_str = (None, False, 0, 0.0, float("nan"))
    falsy_no_zero = (None, False, "", float("nan"))
    conf = draw(config)
    hypothesis.assume(conf.is_smudgable())
    obj = copy.deepcopy(conf.config)
    services: list[dict[str, Any]] = list(obj["services"].values())
    if "global" in obj:
        services.append(obj["global"])
    assert all(isinstance(x, dict) for x in services), (
        "is_smudgable_vault_test_config guard failed to "
        "ensure each settings dict is a dict"
    )
    for service in services:
        for key in ("phrase",):
            value = service.get(key)
            if not _types.js_truthiness(value) and value != "":
                service[key] = draw(strategies.sampled_from(falsy_no_str))
        for key in (
            "notes",
            "key",
            "length",
            "repeat",
        ):
            value = service.get(key)
            if not _types.js_truthiness(value):
                service[key] = draw(strategies.sampled_from(falsy))
        for key in (
            "lower",
            "upper",
            "number",
            "space",
            "dash",
            "symbol",
        ):
            value = service.get(key)
            if not _types.js_truthiness(value) and value != 0:
                service[key] = draw(strategies.sampled_from(falsy_no_zero))
    hypothesis.assume(obj != conf.config)
    return data.VaultTestConfig(obj, conf.comment, conf.validation_settings)


# Hypothesis decorators
# =====================


def _is_paramset(
    seq: Sequence[pytest_mark.ParameterSet] | Sequence[object], /
) -> TypeIs[Sequence[pytest_mark.ParameterSet]]:
    return all(
        isinstance(argvalue, pytest_mark.ParameterSet) for argvalue in seq
    )


def _get_id(
    argvalue: object,
    ids: Sequence[str | None] | Callable[[Any], str | None] | None,
    i: int,
) -> str | None:  # pragma: no cover[external]
    if (
        isinstance(argvalue, pytest_mark.ParameterSet)
        and argvalue.id is not None
    ):
        return argvalue.id
    if callable(ids):
        result = ids(argvalue)
        return result if result is not None else None
    if isinstance(ids, Sequence):
        result = ids[i]
        return result if result is not None else None
    assert_type(ids, None)
    return None


def _get_examples_data_and_ids(
    *,
    argnames: str | Sequence[str],
    argvalues: Sequence[pytest_mark.ParameterSet] | Sequence[object],
    ids: Sequence[str | None] | Callable[[Any], str | None] | None,
) -> tuple[list[dict[str, Any]], list[str | None]]:
    names = (
        tuple(argnames.split(","))
        if isinstance(argnames, str)
        else tuple(argnames)
    )
    examples_data: list[dict[str, Any]] = []
    final_ids: list[str | None] = []
    k = len(names)

    if _is_paramset(argvalues):
        for i, argvalue in enumerate(argvalues):
            if len(argvalue.values) != k:  # pragma: no cover [failsafe]
                msg = f"not a {k}-tuple: {argvalue!r}"
                raise ValueError(msg)
            examples_data.append(dict(zip(names, argvalue.values)))
            final_ids.append(_get_id(argvalue, ids, i))
    else:
        for i, argvalue in enumerate(argvalues):
            if k > 1:
                if (
                    not isinstance(argvalue, Sequence) or len(argvalue) != k
                ):  # pragma: no cover [failsafe]
                    msg = f"not a {k}-tuple: {argvalue!r}"
                    raise ValueError(msg)
                examples_data.append(dict(zip(names, argvalue)))
            else:
                examples_data.append({names[0]: argvalue})
            final_ids.append(_get_id(argvalue, ids, i))

    return examples_data, final_ids


def explicit_examples(
    argnames: str | Sequence[str],
    argvalues: Sequence[pytest_mark.ParameterSet] | Sequence[object],
    ids: Sequence[str | None] | Callable[[Any], str | None] | None = None,
    *,
    settings: hypothesis.settings | None = None,
) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Decorate a function to take explicit (hypothesis) examples.

    Using the same signature as [`pytest.mark.parametrize`][], we
    replicate the effect of decorating the function with multiple
    [`hypothesis.example`][] calls.  This is useful in particular if the
    exact number of examples isn't known statically.  If the decorated
    function is not already a hypothesis test, we also decorate the
    function with [`hypothesis.given`][] and [`hypothesis.settings`][],
    in a manner that only ever runs the explicit examples.  One obvious
    way of writing the (sentinel) strategy to be passed to
    [`hypothesis.given`][] actually triggers
    [`hypothesis.errors.Unsatisfiable`][], so we are careful to avoid
    that ([Hypothesis bug #4774][H4774]).

    [H4774]: https://github.com/HypothesisWorks/hypothesis/issues/4774

    Args:
        argnames:
            A comma-separated list of argument names, or a sequence of
            argument name strings.
        argvalues:
            A sequence of realizations for the named arguments.  If
            only one argument name is given, then each realization must
            be a single value.  Otherwise, each realization must be a
            (correctly sized) tuple of argument values.
        ids:
            An optional sequence of id strings to use for the
            respective realization, or a callable that takes the
            realization and returns an id string or `None`, or `None`.
            If `None` or if the callable returns `None`, and if
            additionally the argvalue is a pytest parameter set that
            has its `id` set, then use that `id`; else fall back to
            auto-generated IDs.

    Returns:
        A decorator that does the equivalent of

            @hypothesis.example(
                argnames[0]=argvalues[0][0],
                argnames[1]=argvalues[0][1],
                ...
            )
            @hypothesis.example(
                argnames[1]=argvalues[1][0],
                argnames[1]=argvalues[1][1],
                ...
            )
            ...
            @hypothesis.example(
                argnames[0]=argvalues[-1][0],
                argnames[1]=argvalues[-1][1],
                ...
            )
            def f(...) -> ...: ...

        and, if not already a hypothesis test, prepends

            @hypothesis.given(
                argnames[0]=strategies.just(argvalues[0][0]),
                argnames[1]=strategies.just(argvalues[0][1]),
                ...
            )

    Warning:
        Because of the way [`pytest.mark.parametrize`][] and
        [`hypothesis.example`][] work, having multiple
        `explicit_examples` decorators behaves differently from
        multiple [`pytest.mark.parametrize`][] decorators, and
        is not drop-in compatible.  `explicit_examples` adds
        *more examples on the same argument names*, whereas
        [`pytest.mark.parametrize`][] adds *more argument names
        and values to the same set of existing examples*!

    """
    if not argnames or not argvalues:  # pragma: no cover [failsafe]
        msg = "no explicit examples given"
        raise ValueError(msg)

    examples_data, final_ids = _get_examples_data_and_ids(
        argnames=argnames, argvalues=argvalues, ids=ids
    )

    def decorator(f: Callable[..., None], /) -> Callable[..., None]:
        ret = f
        for i, arg in reversed(list(enumerate(examples_data))):
            ex_id = final_ids[i]
            ex = hypothesis.example(**arg)
            ex = (
                ex.via("id={!r}".format(str(ex_id)))  # noqa: UP032
                if ex_id is not None
                else ex
            )
            ret = ex(ret)
        if not hypothesis.is_hypothesis_test(
            f
        ):  # pragma: no branch [external]
            kwargs = {
                k: strategies.just(v) for k, v in examples_data[0].items()
            }
            given = hypothesis.given(**kwargs)
            ret = given(ret)
            new_settings = hypothesis.settings(
                parent=settings,
                phases=[hypothesis.Phase.explicit, hypothesis.Phase.reuse],
            )
            ret = new_settings(ret)
        return ret

    return decorator
