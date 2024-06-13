# CHANGELOG



## v0.1.0 (2024-06-13)

### Chore

* chore: ensure ssh permissions ([`76be670`](https://github.com/leoslf/socks-router/commit/76be6704a281593632f62d99006d5a7e28a790c9))

* chore: verbose ssh flag ([`79295d5`](https://github.com/leoslf/socks-router/commit/79295d590391eb4cabfdb5c3733488ec42a00f05))

* chore: ssh on mac ([`1cd4999`](https://github.com/leoslf/socks-router/commit/1cd4999d0327b6647ae25af9910a3c23ef301685))

* chore: sshd config on mac ([`2265c34`](https://github.com/leoslf/socks-router/commit/2265c348d13db80460ea2addb89fcc812227f00e))

* chore: test ssh ([`469b528`](https://github.com/leoslf/socks-router/commit/469b528144f43ea282efffa092759a82bfdb2539))

* chore: restart ssh ([`470e909`](https://github.com/leoslf/socks-router/commit/470e909392c8f3453f7a4698365002d629c9e6cd))

* chore: restart ssh ([`a39b51c`](https://github.com/leoslf/socks-router/commit/a39b51cd0f7f6fd655d6609d106a7e3754b21daf))

* chore: ssh config ([`3321fab`](https://github.com/leoslf/socks-router/commit/3321fab3fbe5aa27e0daeafb3797a4d098ce4db9))

* chore: set AddressFamily to any in sshd_config ([`2aadf01`](https://github.com/leoslf/socks-router/commit/2aadf01e6f53b194267dac65b7251e3edacfda7a))

* chore: added debug log on OSError ([`ebc4331`](https://github.com/leoslf/socks-router/commit/ebc4331aa4c1b68bcf45a9acd4640f692011c74f))

* chore: improve exception logging ([`2196806`](https://github.com/leoslf/socks-router/commit/219680671098934b20fc95fd94241fb6325a7fa2))

* chore: changed log level in utils ([`6420457`](https://github.com/leoslf/socks-router/commit/6420457a66b938a3c0073afa399ade5e604b3a6d))

* chore: better handling for exceptions ([`26fbe30`](https://github.com/leoslf/socks-router/commit/26fbe30f66e9ae23b8f6c57a18e5e3a13905f815))

* chore: removed unused code ([`dfb14f6`](https://github.com/leoslf/socks-router/commit/dfb14f699183c7377b796bb86f7d0951d8a11016))

* chore: fixed typo ([`05fac3e`](https://github.com/leoslf/socks-router/commit/05fac3e46c7d60aa144865f965ae642d2472fb5f))

* chore: added pytest into pre-commit hooks ([`bd3aca2`](https://github.com/leoslf/socks-router/commit/bd3aca2ce2bd22800988f45eae86aeb3197f9ff4))

* chore: fixed linter errors ([`fd16a0c`](https://github.com/leoslf/socks-router/commit/fd16a0ce77cf55d86d96cc8a93e2c8842bb1604c))

* chore: initial check-in ([`565e063`](https://github.com/leoslf/socks-router/commit/565e063525bfd8f894b98749ffbbeaafbfe34afd))

### Ci

* ci: fix default branch checking ([`557bcbf`](https://github.com/leoslf/socks-router/commit/557bcbf4117319bfa575df8073220b3ca24b3b03))

* ci: fix ssh command test ([`1d4903f`](https://github.com/leoslf/socks-router/commit/1d4903fbea226df11d804d3e142bbaa392c0d3f1))

* ci: fix ssh command test ([`bd9fdb6`](https://github.com/leoslf/socks-router/commit/bd9fdb61f5b5b0fba3f4f9215e5eef8802d61d62))

* ci: use native traceback in pytest ([`52c2ff3`](https://github.com/leoslf/socks-router/commit/52c2ff3faa179f3345b24cc2fa5bfa1ee4d05db9))

* ci: ssh config ([`09bad9e`](https://github.com/leoslf/socks-router/commit/09bad9e7c33a3e97bb15585f037a0544512eeb16))

* ci: ssh MaxAuthTries 100 ([`91c0112`](https://github.com/leoslf/socks-router/commit/91c0112a1926598693de91e66293141e2746ebc6))

* ci: ssha ([`813398e`](https://github.com/leoslf/socks-router/commit/813398e56f7d1b8c7966e797a520a41c93c01f9d))

* ci: ssh ([`18b7961`](https://github.com/leoslf/socks-router/commit/18b79618bcd2506e376cb070af32bdeba9f9133b))

* ci: ssh config ([`b6a4c1f`](https://github.com/leoslf/socks-router/commit/b6a4c1fe70f0c770c845e30f2f344bc332d45934))

* ci: host key ([`c8bb0f0`](https://github.com/leoslf/socks-router/commit/c8bb0f095e251e95cfb2cc5602db732eb5c28696))

* ci: attempt to connect to sshd first ([`a5f8e6c`](https://github.com/leoslf/socks-router/commit/a5f8e6cd65f5f6cf3fdd5a53d791df7a20c17b0b))

* ci: leave ListenAddress alone ([`3dbe22d`](https://github.com/leoslf/socks-router/commit/3dbe22df6a224e372bc10bc97c1b1845af192aff))

* ci: write logs to junitxml ([`3409343`](https://github.com/leoslf/socks-router/commit/340934324a17f5e1d7ed0a73d27c045676eb4043))

* ci: lock mypy at 415d49f25b6315cf1b7a04046a942246a033498d ([`3ea10c6`](https://github.com/leoslf/socks-router/commit/3ea10c6d075733697480d9cb3d36c1e25024e684))

* ci: add colors to github actions ([`9837b45`](https://github.com/leoslf/socks-router/commit/9837b450bf44483198fd4e7a3fda255d37d91c40))

* ci: add colors to github actions ([`699ea7b`](https://github.com/leoslf/socks-router/commit/699ea7b0b4a0c171b46c0379acbee25d2627e5db))

* ci: always proceed to consolidation and sonarqube ([`970442b`](https://github.com/leoslf/socks-router/commit/970442bd962ca37a1f3a8eac4cd318e29f5df68e))

* ci: sed compatibility ([`056406f`](https://github.com/leoslf/socks-router/commit/056406f0cdb703d39108566574be9e12b2b05e69))

* ci: quoting ([`9e1e5da`](https://github.com/leoslf/socks-router/commit/9e1e5da7c0b6033764759cf7e878c763950a8da4))

* ci: quoting ([`6b3e8da`](https://github.com/leoslf/socks-router/commit/6b3e8daf3300ea64147e79b9a08b63fa4525c533))

* ci: accomodate mac ([`c9e2558`](https://github.com/leoslf/socks-router/commit/c9e2558ff9c4aa2140c562ad5c8e0eb8c6548e6a))

* ci: set +e in start-ssh-agent ([`52438a6`](https://github.com/leoslf/socks-router/commit/52438a633abb2a1c4796845bb833814b08967ab9))

* ci: fix ssh-keygen ([`d426fd3`](https://github.com/leoslf/socks-router/commit/d426fd377da90174538c0d753dead2d5e90d58d5))

* ci: specify path for id_rsa ([`7eed841`](https://github.com/leoslf/socks-router/commit/7eed8410fdb8b3034f4a02e90f7dffd41c9050d2))

* ci: fixed permission issue ([`858bee1`](https://github.com/leoslf/socks-router/commit/858bee12ebf3a33a559d1fb7b0887603dc1d3046))

* ci: fixed quotes in action ([`1c55f25`](https://github.com/leoslf/socks-router/commit/1c55f25876a5498ef5c84431db45c8bb1880ff1e))

* ci: added shell parameter in action ([`55f9d19`](https://github.com/leoslf/socks-router/commit/55f9d19b9ca937a831d7c49ff3c34e8da549512c))

* ci: setup sshd ([`e2b3a1a`](https://github.com/leoslf/socks-router/commit/e2b3a1af63227c22113609f14aa3ac0b2ae94d99))

* ci: fixed pipeline ([`b207d42`](https://github.com/leoslf/socks-router/commit/b207d420bf33759bdbb249136f979de394fc1c48))

* ci: fixed sphinx ([`1190ed4`](https://github.com/leoslf/socks-router/commit/1190ed43fb897dd899b8c76260a10767ce50a2e5))

* ci: fixed sonar-project.properties ([`dd1bf6d`](https://github.com/leoslf/socks-router/commit/dd1bf6db3b559392b50eafce278d6464cd5ec3cb))

* ci: use --non-interactive in ci ([`b7c2aea`](https://github.com/leoslf/socks-router/commit/b7c2aead47729fa2faf950cff80c1204c9b3bf00))

* ci: use sonarqube on-premise ([`d5c919c`](https://github.com/leoslf/socks-router/commit/d5c919c0712636471fcab6e0b0ae4abe5a26ff75))

* ci: added python version ([`d62a933`](https://github.com/leoslf/socks-router/commit/d62a9338df2212a25500e57f9c201fca657f6b87))

* ci: added python version ([`319b018`](https://github.com/leoslf/socks-router/commit/319b018672e22e8342eaf1181da687a798be6de1))

* ci: fix setup ([`4ef0956`](https://github.com/leoslf/socks-router/commit/4ef0956d9601ae7c068f86dcccb46e696ae8b2ba))

* ci: added --enable-incomplete-feature=NewGenericSyntax ([`9f746a9`](https://github.com/leoslf/socks-router/commit/9f746a9b7d996e2c7953f9dfc572b32afc2504b3))

### Feature

* feat: implemented socks-router ([`a59afc2`](https://github.com/leoslf/socks-router/commit/a59afc25cf8d97be3e682259f068e082a767f219))

### Fix

* fix: show sshd_config ([`9c010c3`](https://github.com/leoslf/socks-router/commit/9c010c3ad12a69d7e5a4dcd2a7ddeafbdef1579f))

* fix: pattern matching should match any port if port not given in routing table ([`b71b215`](https://github.com/leoslf/socks-router/commit/b71b215c134a33f200604effb9e4d0a7122d44d3))

### Performance

* perf: fixed connection reset problem ([`422da33`](https://github.com/leoslf/socks-router/commit/422da331e02366fd113525b90face635cba70f32))

### Refactor

* refactor: refactored pattern logic ([`a61d4e0`](https://github.com/leoslf/socks-router/commit/a61d4e0622f0ad209c27152c10aa741a75ae68c1))

* refactor: use Annotated to handle struct packing ([`3508f7a`](https://github.com/leoslf/socks-router/commit/3508f7a11026cbd22c39a6c97c62a444aec36344))

* refactor: extends ThreadingTCPServer ([`f1003fb`](https://github.com/leoslf/socks-router/commit/f1003fb01d245b2ff60aa46b02a0920a60c30b54))

* refactor: fixed typing ([`cd79854`](https://github.com/leoslf/socks-router/commit/cd79854cdbbbe0030dd12ce63e71e4325aeabb31))

* refactor: fixed ruff errors ([`47a92bb`](https://github.com/leoslf/socks-router/commit/47a92bb867c0d762463d1855f27d6335edd6b6c0))

### Test

* test: force ipv4 for destination for when_upstream_server_does_not_behave ([`26db9c7`](https://github.com/leoslf/socks-router/commit/26db9c76a2ffc370f3b68bcc821f751861e9da0a))

* test: remove fixture to fix ScopeMismatch ([`6f34b1c`](https://github.com/leoslf/socks-router/commit/6f34b1c51a822c0c451ad54459471d0f4d490640))

* test: fix linux test case ([`ecb17fa`](https://github.com/leoslf/socks-router/commit/ecb17fab2bc4a0ed29afe0f1ef58c606841b6b9f))

* test: refactored proxies ([`174c15d`](https://github.com/leoslf/socks-router/commit/174c15d04a8e42868ea82ad282686a124421f1bd))

* test: use StringIO for stdout and stderr ([`7fac1a0`](https://github.com/leoslf/socks-router/commit/7fac1a066ee28a59cfa46acae4a59bd37336fbd2))

* test: specify identity file ([`7954c1a`](https://github.com/leoslf/socks-router/commit/7954c1ac1245b2e2617a029bdb318fa8600f8b2b))

* test: cover router ([`aceea3e`](https://github.com/leoslf/socks-router/commit/aceea3e4c416da9b5b5b1b3a212d38a6c8584baf))

* test: cover router ([`4657e15`](https://github.com/leoslf/socks-router/commit/4657e1520fcca743994d9eb4cfe3119936e4b63d))

* test: fully covered utils ([`993c071`](https://github.com/leoslf/socks-router/commit/993c0716075e72b7f4874728b2a5c8f42e59679e))

* test: cover read_socket ([`21a5f76`](https://github.com/leoslf/socks-router/commit/21a5f768812d76487d879818d04ea3143110f9d0))

* test: cover utils ([`cf5f6d4`](https://github.com/leoslf/socks-router/commit/cf5f6d4d16445114353d3a1d657e8ea141e2c8fb))

* test: testing router ([`8cbf208`](https://github.com/leoslf/socks-router/commit/8cbf208fce89b54651e178a6beb2e3f8ac001eda))

* test: fully test cli ([`b48388f`](https://github.com/leoslf/socks-router/commit/b48388f676d534a7636cf09303d67e45d6aee46e))

* test: added test case to ensure non-sock5 versions are not handled ([`ffd2d75`](https://github.com/leoslf/socks-router/commit/ffd2d75f2556923901bf0496fbcf73a2ae284fc3))

* test: testing socks-router with itself ([`4bee59f`](https://github.com/leoslf/socks-router/commit/4bee59f2847b9ff911f2263fdfab580d127280f8))

* test: added tests to router ([`5635fc9`](https://github.com/leoslf/socks-router/commit/5635fc9a44f49b6ecdb38659ee67a3cbba5060df))

### Unknown

* wip: debug on CI ([`b962c3a`](https://github.com/leoslf/socks-router/commit/b962c3a4004e971c448b28c88b38f9d923dfc2b5))

* wip: debug on CI ([`60c555d`](https://github.com/leoslf/socks-router/commit/60c555d1bec1cb043909f5e19ec5e9d74fbe9b98))

* wip: debug on CI ([`7a23bad`](https://github.com/leoslf/socks-router/commit/7a23bad5c6737c2099b874859fb1eefeabfb87ef))

* wip: debug on CI ([`6c4cc9b`](https://github.com/leoslf/socks-router/commit/6c4cc9b21f0e756501571d2f6cc96ff617034502))
