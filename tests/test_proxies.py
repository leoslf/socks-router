from socks_router.proxies import LiteralProxy


def describe_proxies():
    def describe_LiteralProxy():
        def it_should_passthrough():
            # given
            original: dict[str, str] = {
                "foo": "bar",
            }
            proxy: dict[str, str] = LiteralProxy.create(original)
            assert proxy["foo"] == "bar"

            original["foo"] = "baz"
            assert proxy["foo"] == "baz"
