from __future__ import annotations

import contextlib
import os.path
import re
import sys
from typing import Any
from typing import Callable
from typing import Generator
from typing import Iterable
from typing import NamedTuple
from typing import Optional as TOptional
from typing import overload
from typing import Protocol
from typing import Tuple
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing_extensions import Self, TypeAlias


class _Schema(Protocol):
    def check(self, v: object) -> None:
        ...

    def apply_defaults(self, v: object) -> Any:
        ...

    def remove_defaults(self, v: object) -> Any:
        ...


class _Validator(Protocol):
    def check(self, dct: object) -> None:
        ...

    def apply_default(self, dct: object) -> Any:
        ...

    def remove_default(self, dct: object) -> Any:
        ...


_Check: TypeAlias = Callable[[object], None]


class ValidationError(ValueError):
    @overload
    def __init__(self, error_msg: str) -> None: ...
    @overload
    def __init__(self, error_msg: Self, ctx: str | None = None) -> None: ...

    def __init__(self, error_msg: Self, ctx: str | None = None) -> None:
        super().__init__(error_msg)
        self.error_msg = error_msg
        self.ctx = ctx

    def __str__(self):
        out = '\n'
        err = self
        while err.ctx is not None:
            out += f'==> {err.ctx}\n'
            err = err.error_msg
        out += f'=====> {err.error_msg}'
        return out


class _Missing(NamedTuple):
    def __repr__(self):
        return 'MISSING'


MISSING = _Missing()


@contextlib.contextmanager
def validate_context(msg: str) -> Generator[None, Any, None]:
    try:
        yield
    except ValidationError as e:
        _, _, tb = sys.exc_info()
        raise ValidationError(e, ctx=msg).with_traceback(tb) from None


@contextlib.contextmanager
def reraise_as(tp: type[Exception]) -> Generator[None, Any, None]:
    try:
        yield
    except ValidationError as e:
        _, _, tb = sys.exc_info()
        raise tp(e).with_traceback(tb) from None


def _check_optional(self, dct):
    if self.key not in dct:
        return
    with validate_context(f'At key: {self.key}'):
        self.check_fn(dct[self.key])


def _apply_default_optional(self, dct):
    dct.setdefault(self.key, self.default)


def _remove_default_optional(self, dct):
    if dct.get(self.key, MISSING) == self.default:
        del dct[self.key]


def _require_key(self, dct):
    if self.key not in dct:
        raise ValidationError(f'Missing required key: {self.key}')


def _check_required(self, dct):
    _require_key(self, dct)
    _check_optional(self, dct)


@property
def _check_fn_recurse(self):
    def check_fn(val):
        validate(val, self.schema)
    return check_fn


def _apply_default_required_recurse(self, dct):
    dct[self.key] = apply_defaults(dct[self.key], self.schema)


def _remove_default_required_recurse(self, dct):
    dct[self.key] = remove_defaults(dct[self.key], self.schema)


def _apply_default_optional_recurse(self, dct):
    if self.key not in dct:
        _apply_default_optional(self, dct)
    _apply_default_required_recurse(self, dct)


def _remove_default_optional_recurse(self, dct):
    if self.key in dct:
        _remove_default_required_recurse(self, dct)
        _remove_default_optional(self, dct)


def _get_check_conditional(inner):
    def _check_conditional(self, dct):
        if dct.get(self.condition_key, MISSING) == self.condition_value:
            inner(self, dct)
        elif (
                self.condition_key in dct and
                self.ensure_absent and self.key in dct
        ):
            if hasattr(self.condition_value, 'describe_opposite'):
                explanation = self.condition_value.describe_opposite()
            else:
                explanation = f'is not {self.condition_value!r}'
            raise ValidationError(
                f'Expected {self.key} to be absent when {self.condition_key} '
                f'{explanation}, found {self.key}: {dct[self.key]!r}',
            )
    return _check_conditional


def _apply_default_conditional_optional(self, dct):
    if dct.get(self.condition_key, MISSING) == self.condition_value:
        _apply_default_optional(self, dct)


def _remove_default_conditional_optional(self, dct):
    if dct.get(self.condition_key, MISSING) == self.condition_value:
        _remove_default_optional(self, dct)


def _apply_default_conditional_recurse(self, dct):
    if dct.get(self.condition_key, MISSING) == self.condition_value:
        _apply_default_required_recurse(self, dct)


def _remove_default_conditional_recurse(self, dct):
    if dct.get(self.condition_key, MISSING) == self.condition_value:
        _remove_default_required_recurse(self, dct)


def _no_additional_keys_check(self, dct):
    extra = sorted(set(dct) - set(self.keys))
    if extra:
        extra_s = ', '.join(str(x) for x in extra)
        keys_s = ', '.join(str(x) for x in self.keys)
        raise ValidationError(
            f'Additional keys found: {extra_s}.  '
            f'Only these keys are allowed: {keys_s}',
        )


def _warn_additional_keys_check(self, dct):
    extra = sorted(set(dct) - set(self.keys))
    if extra:
        self.callback(extra, self.keys, dct)


class Required(NamedTuple):
    key: str
    check_fn: _Check

    def check(self, dct):
        return _check_required(self, dct)

    def apply_default(self, dct) -> None:
        pass

    def remove_default(self, dct) -> None:
        pass


class RequiredRecurse(NamedTuple):
    key: str
    schema: _Schema

    @property
    def check_fn(self):
        def check_fn(val):
            validate(val, self.schema)
        return check_fn

    def check(self, dct):
        return _check_required(self, dct)

    def apply_default(self, dct):
        return _apply_default_required_recurse(self, dct)

    def remove_default(self, dct):
        return _remove_default_required_recurse(self, dct)


class Optional(NamedTuple):
    key: str
    check_fn: _Check
    default: object

    def check(self, dct):
        return _check_optional(self, dct)

    def apply_default(self, dct):
        return _apply_default_optional(self, dct)

    def remove_default(self, dct):
        return _remove_default_optional(self, dct)


class OptionalRecurse(NamedTuple):
    key: str
    schema: _Schema
    default: object

    @property
    def check_fn(self):
        def check_fn(val):
            validate(val, self.schema)
        return check_fn

    def check(self, dct) -> None:
        return _check_optional(self, dct)

    def apply_default(self, dct):
        return _apply_default_optional_recurse(self, dct)

    def remove_default(self, dct):
        return _remove_default_optional_recurse(self, dct)


class OptionalNoDefault(NamedTuple):
    key: str
    check_fn: _Check

    def check(self, dct):
        return _check_optional(self, dct)

    def apply_default(self, dct):
        pass

    def remove_default(self, dct):
        pass


class Conditional(NamedTuple):
    key: str
    check_fn: _Check
    condition_key: object
    condition_value: object
    ensure_absent: bool = False

    def check(self, dct):
        return _get_check_conditional(_check_required)(self, dct)

    def apply_default(self, dct):
        pass

    def remove_default(self, dct):
        pass


class ConditionalOptional(NamedTuple):
    key: str
    check_fn: _Check
    default: object
    condition_key: object
    condition_value: object
    ensure_absent: bool = False

    def check(self, dct):
        return _get_check_conditional(_check_optional)(self, dct)

    def apply_default(self, dct):
        return _apply_default_conditional_optional(self, dct)

    def remove_default(self, dct):
        return _remove_default_conditional_optional(self, dct)


class ConditionalRecurse(NamedTuple):
    key: str
    schema: _Schema
    condition_key: object
    condition_value: object
    ensure_absent: bool = False

    @property
    def check_fn(self):
        def check_fn(val):
            validate(val, self.schema)
        return check_fn

    def check(self, dct):
        return _get_check_conditional(_check_required)(self, dct)

    def apply_default(self, dct):
        return _apply_default_conditional_recurse(self, dct)

    def remove_default(self, dct):
        return _remove_default_conditional_recurse(self, dct)


class NoAdditionalKeys(NamedTuple):
    keys: Iterable[str]

    def check(self, dct):
        return _no_additional_keys_check(self, dct)

    def apply_default(self, dct):
        pass

    def remove_default(self, dct):
        pass


class WarnAdditionalKeys(NamedTuple):
    keys: Iterable[str]
    callback: Callable[..., Any]

    def check(self, dct):
        return _warn_additional_keys_check(self, dct)

    def apply_default(self, dct):
        pass

    def remove_default(self, dct):
        pass


class Map(
    NamedTuple(
        'Map',
        (
            ('object_name', str),
            ('id_key', TOptional[str]),
            ('items', Tuple[object, ...]),
        ),
    ),
):
    __slots__ = ()

    def __new__(cls, object_name: str, id_key: str | None, *items: object):
        return super().__new__(cls, object_name, id_key, items)

    def check(self, v):
        if not isinstance(v, dict):
            raise ValidationError(
                f'Expected a {self.object_name} map but got a '
                f'{type(v).__name__}',
            )
        if self.id_key is None:
            context = f'At {self.object_name}()'
        else:
            key_v_s = v.get(self.id_key, MISSING)
            context = f'At {self.object_name}({self.id_key}={key_v_s!r})'
        with validate_context(context):
            for item in self.items:
                item.check(v)

    def apply_defaults(self, v):
        ret = v.copy()
        for item in self.items:
            item.apply_default(ret)
        return ret

    def remove_defaults(self, v):
        ret = v.copy()
        for item in self.items:
            item.remove_default(ret)
        return ret


class Array(NamedTuple):
    of: _Schema
    allow_empty: bool = True

    def check(self, v):
        check_array(check_any)(v)
        if not self.allow_empty and not v:
            raise ValidationError(
                f"Expected at least 1 '{self.of.object_name}'",
            )
        for val in v:
            validate(val, self.of)

    def apply_defaults(self, v):
        return [apply_defaults(val, self.of) for val in v]

    def remove_defaults(self, v):
        return [remove_defaults(val, self.of) for val in v]


class Not(NamedTuple):
    val: object

    def describe_opposite(self):
        return f'is {self.val!r}'

    def __eq__(self, other: object):
        return other is not MISSING and other != self.val


class NotIn(NamedTuple('NotIn', (('values', Tuple[object, ...]),))):
    __slots__ = ()

    def __new__(cls, *values: object):
        return super().__new__(cls, values=values)

    def describe_opposite(self) -> str:
        return f'is any of {self.values!r}'

    def __eq__(self, other: object):
        return other is not MISSING and other not in self.values


class In(NamedTuple('In', (('values', Tuple[object, ...]),))):
    __slots__ = ()

    def __new__(cls, *values: object):
        return super().__new__(cls, values=values)

    def describe_opposite(self) -> str:
        return f'is not any of {self.values!r}'

    def __eq__(self, other: object):
        return other is not MISSING and other in self.values


def check_any(_):
    pass


def check_type(tp: type, typename: str | None = None) -> _Check:
    def check_type_fn(v: object):
        if not isinstance(v, tp):
            typename_s = typename or tp.__name__
            raise ValidationError(
                f'Expected {typename_s} got {type(v).__name__}',
            )
    return check_type_fn


check_bool = check_type(bool)
check_bytes = check_type(bytes)
check_int = check_type(int)
check_string = check_type(str, typename='string')
check_text = check_type(str, typename='text')


def check_one_of(possible: Iterable[object]) -> _Check:
    def check_one_of_fn(v: object) -> None:
        if v not in possible:
            possible_s = ', '.join(str(x) for x in sorted(possible))
            raise ValidationError(
                f'Expected one of {possible_s} but got: {v!r}',
            )
    return check_one_of_fn


def check_regex(v: object) -> None:
    try:
        re.compile(v)
    except re.error:
        raise ValidationError(f'{v!r} is not a valid python regex')


def check_array(inner_check: _Check) -> _Check:
    def check_array_fn(v):
        if not isinstance(v, (list, tuple)):
            raise ValidationError(
                f'Expected array but got {type(v).__name__!r}',
            )

        for i, val in enumerate(v):
            with validate_context(f'At index {i}'):
                inner_check(val)
    return check_array_fn


def check_and(*fns: _Check) -> _Check:
    def check(v: object) -> None:
        for fn in fns:
            fn(v)
    return check


def validate(v, schema: _Schema):
    schema.check(v)
    return v


def apply_defaults(v, schema: _Schema):
    return schema.apply_defaults(v)


def remove_defaults(v, schema: _Schema):
    return schema.remove_defaults(v)


def load_from_filename(
        filename: str,
        schema: _Schema,
        load_strategy: Callable[[str], Any],
        exc_tp: type[Exception] = ValidationError,
        *,
        display_filename: str | None = None,
):
    display_filename = display_filename or filename
    with reraise_as(exc_tp):
        if not os.path.isfile(filename):
            raise ValidationError(f'{display_filename} is not a file')

        with validate_context(f'File {display_filename}'):
            try:
                with open(filename, encoding='utf-8') as f:
                    contents = f.read()
            except UnicodeDecodeError as e:
                raise ValidationError(str(e))

            try:
                data = load_strategy(contents)
            except Exception as e:
                raise ValidationError(str(e))

            validate(data, schema)
            return apply_defaults(data, schema)
