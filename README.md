# SK_SKB_TESTS

In one terminal:

```bash
make
vagrant up
vagrant ssh
cd /vagrant && sudo ./sk_skb_tests
```

In another:

```bash
vagrant ssh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```