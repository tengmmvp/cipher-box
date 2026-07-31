"""``require_unlocked`` 装饰器测试（项目唯一的锁定态守卫）。

覆盖 ``src/ui/controllers/_locked_guard.py``：
- 锁定态（``self._locked=True``）直接 return None，不调被装饰方法。
- 解锁态透传任意 args/kwargs 调用被装饰方法。
- ``@wraps`` 保留被装饰方法的 ``__name__`` / ``__doc__``。

被装饰方法均为返回 None 的 Qt 槽，故守卫特化为 ``Callable[..., None]``；测试据此
断言锁定态与正常态返回值均为 None，但仅在解锁态真正调用了方法体。
"""

from src.ui.controllers._locked_guard import require_unlocked


class _Host:
    """锁定态守卫宿主：``_locked`` 由用例切换，``calls`` 记录方法体执行情况。"""

    def __init__(self) -> None:
        self._locked = False
        self.calls: list[tuple[tuple, dict]] = []

    @require_unlocked
    def do_work(self, *args, **kwargs) -> None:
        """记录调用参数，供断言守卫的透传/跳过行为。"""
        self.calls.append((args, kwargs))


class TestRequireUnlocked:
    def test_locked_state_returns_none_without_calling_method(self):
        """锁定态：守卫 return None 且被装饰方法不执行。"""
        host = _Host()
        host._locked = True

        result = host.do_work('a', key='v')

        assert result is None
        assert host.calls == []

    def test_unlocked_state_passes_through_args_and_kwargs(self):
        """解锁态：原样透传位置参数与关键字参数给被装饰方法。"""
        host = _Host()
        host._locked = False

        host.do_work('positional', 42, flag=True, name='测试')

        assert len(host.calls) == 1
        args, kwargs = host.calls[0]
        assert args == ('positional', 42)
        assert kwargs == {'flag': True, 'name': '测试'}

    def test_unlocked_state_returns_none(self):
        """被装饰方法返回 None（槽语义），守卫不改变返回类型。"""
        host = _Host()
        host._locked = False
        assert host.do_work() is None

    def test_wraps_preserves_method_name_and_doc(self):
        """``@wraps`` 保留被装饰方法的 __name__ / __doc__，便于诊断与 Qt 反射。"""
        assert _Host.do_work.__name__ == 'do_work'
        assert _Host.do_work.__doc__ is not None
        assert '记录调用参数' in _Host.do_work.__doc__

    def test_transition_from_locked_to_unlocked_executes(self):
        """同一宿主由锁定切到解锁后，方法恢复正常执行（状态驱动而非构造期固化）。"""
        host = _Host()
        host._locked = True
        host.do_work()
        assert host.calls == []

        host._locked = False
        host.do_work('now')
        assert len(host.calls) == 1
        assert host.calls[0][0] == ('now',)
