# Unix 점검 기준 — AIX

## 기본 경로 및 명령어
| 항목 | 경로/명령 |
|------|---------|
| 서비스 관리 | `lssrc -a`, `stopsrc -s <서비스>`, `startsrc -s <서비스>` |
| inetd 재시작 | `refresh -s inetd` |
| 비밀번호 정책 | `/etc/security/user` |
| Shadow 파일 | `/etc/security/passwd` |
| 계정 잠금 | `/etc/security/user` → `loginretries` |
| 패키지 관리 | `instfix -i`, `smitty installp` |
| 로그 파일 | `/var/adm/` |
| NTP | `/etc/ntp.conf`, `ntpq -pn` |
| 버전 확인 | `oslevel -s`, `uname -a` |
| 방화벽 | IPFilter (`/etc/ipf/ipf.conf`), TCP Wrapper |
| 계정 삭제 | `rmuser <계정>` |
| UID 변경 | `chuser id=<UID> <계정>` |

---

## ⚠️ 점검 기준 참조 규칙 (필수)

이 파일의 점검 항목(U-01 ~ U-67)을 평가할 때 — 직접 평가하든, 서브에이전트에게 위임하든 — 다음을 반드시 지킨다:

1. **기준은 이 파일을 Read 도구로 직접 읽어 확인**한다. 기억·이전 대화 요약·컴팩트 summary에서 기준을 가져오지 않는다 (요약은 손실 압축이므로 selector·임계값·예외조건이 변형될 수 있음).
2. 서브에이전트에게 위임할 때는 기준을 프롬프트에 인라인으로 박지 말고, **다음과 같이 지시**한다:
   > "판단 기준은 `unix/aix/CLAUDE.md`의 U-XX 섹션을 Read 도구로 읽어 그대로 적용하라. 요약·재해석·축약 금지. 명시된 selector/조건이 하나라도 누락되면 취약으로 판정."
3. 점검 결과 받은 뒤 이중검토 단계에서 양호 판정 1~2건을 샘플링해 이 파일의 기준과 직접 대조한다. 기준 미스매치 발견 시 해당 코드(전체) 재점검을 즉시 트리거한다.

---

## 점검 항목 (U-01 ~ U-67)

### U-01 (상) | root 계정 원격 접속 제한
- **양호**: `/etc/ssh/sshd_config` 에 **`PermitRootLogin no` 가 명시 설정**되어 있어야 양호 (주석 처리된 `#PermitRootLogin no` 는 OpenSSH 기본값에 의존하므로 **취약**)
- **취약**: `PermitRootLogin yes` 설정 OR `PermitRootLogin` 라인이 주석 처리되어 있거나 부재 (명시 설정 없음 → 기본값 의존 → 취약)
- **점검**:
  - SSH: `grep -E "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config` (주석 라인 제외 매칭)
  - Telnet: `grep rlogin /etc/security/user | grep root`
- **조치**: `/etc/ssh/sshd_config` 의 `#PermitRootLogin` 주석 제거 후 `PermitRootLogin no` 로 명시; `/etc/security/user` → `rlogin = false` (root 섹션); sshd 재시작

### U-02 (상) | 비밀번호 관리정책 설정
- **양호**: 영문/숫자/특수문자 포함 + 최소 8자 이상 + 최소 사용기간 1일 + 최대 사용기간 90일 + 비밀번호 기억 4회 이상 (5조건 모두 충족)
- **점검**: `grep -A 20 "^default:" /etc/security/user | grep -E "minage|maxage|minalpha|minother|minspecialchar|minlen|histsize"`
- **조치**: `/etc/security/user` default 섹션:
  ```
  minage=1
  maxage=12
  minalpha=2
  minother=2
  minspecialchar=1
  minlen=8
  mindiff=4
  histsize=4
  ```

### U-03 (상) | 계정 잠금 임계값 설정
- **양호**: 임계값(`loginretries`) 10회 이하 **AND** 잠금 해제 대기 시간(`loginreenable`) > 0
  - `loginreenable = 0` 은 자동 해제 비활성으로도 해석되지만, KISA 점검 기준상 잠금 보호 무효화로 간주 → **취약**
- **점검**: `grep -A 20 "^default:" /etc/security/user | grep -E "loginretries|loginreenable"`
- **조치**: `/etc/security/user` default 섹션 → `loginretries = 3` (3~10 권고), `loginreenable = 10` (10분 권고, 0 금지)

### U-04 (상) | 비밀번호 파일 보호
- **양호**: /etc/security/passwd에 암호화된 비밀번호
- **점검**: `cat /etc/security/passwd | head -10`
  - AIX는 기본적으로 /etc/security/passwd에 암호화 저장
- **조치**: 기본 설정 유지 (AIX는 기본 암호화)

### U-05 (상) | root 이외의 UID '0' 금지
- **양호**: UID=0이 root만
- **점검**: `awk -F: '($3==0)' /etc/passwd`
- **조치**: `chuser id=<새UID> <계정명>`

### U-06 (상) | 사용자 계정 su 기능 제한
- **양호**: wheel 그룹만 su 사용
- **점검**: `ls -l /usr/bin/su`; `grep wheel /etc/group`
- **조치**: `groupadd wheel`; `chgrp wheel /usr/bin/su`; `chmod 4750 /usr/bin/su`; `usermod -G wheel <계정>`

### U-07 (하) | 불필요한 계정 제거
- **양호**: 불필요한 계정 없음
- **점검**: `cat /etc/passwd`; `last | head -20`
- **조치**: `rmuser <계정명>`

### U-08 (중) | 관리자 그룹에 최소한의 계정 포함
- **양호**: root 그룹에 불필요 계정 없음
- **점검**: `grep "^root:" /etc/group`
- **조치**: `chgrpmem -m - <사용자> root`

### U-09 (하) | 계정이 존재하지 않는 GID 금지
- **양호**: **GID >= 999** 인 그룹 중 구성원이 없는 그룹이 존재하지 않음
- **취약**: **GID >= 999** 인 그룹 중 구성원이 없는 그룹이 1개 이상 존재
- **N/A**: GID < 999 (시스템 그룹) — 임의 화이트리스트 판단 금지, **GID 값으로만** 점검 대상 결정
- **점검**: `awk -F: '$3 >= 999 && $4 == "" {print $1, $3}' /etc/group`
- **조치**: `rmgroup <그룹명>` (GID >= 999 빈 그룹만 대상)

### U-10 (중) | 동일한 UID 금지
- **양호**: 중복 UID 없음
- **점검**: `awk -F: '{print $3}' /etc/passwd | sort | uniq -d`
- **조치**: `chuser id=<새UID> <계정명>`

### U-11 (하) | 사용자 shell 점검
- **양호**: 불필요 계정에 `/bin/false`
- **점검**: `awk -F: '($7 != "/bin/false")' /etc/passwd` (daemon, bin, sys 등)
- **조치**: `chuser shell=/bin/false <계정명>`

### U-12 (하) | 세션 종료 시간 설정
- **양호**: TMOUT 600초 이하
- **점검**: `grep TMOUT /etc/profile`
- **조치**: `/etc/profile`에 `TMOUT=600; export TMOUT`

### U-13 (중) | 안전한 비밀번호 암호화 알고리즘 사용
- **양호**: SHA-256 또는 SHA-512
- **점검**:
  - `head -3 /etc/security/passwd` (암호화 알고리즘 확인)
  - `grep pwd_algorithm /etc/security/login.cfg 2>/dev/null`
- **조치**: `chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=SHA512`

### U-14 (상) | root 홈·PATH 설정
- **양호**: PATH에 `.` 없음
- **점검**: `echo $PATH | grep -E "(^|:)\.(:|$)"`; `grep PATH /etc/profile /root/.profile 2>/dev/null`
- **조치**: PATH에서 `.` 제거

### U-15 (상) | 파일 및 디렉터리 소유자 설정
- **양호**: 소유자 없는 파일 없음
- **점검**: `find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null`
- **조치**: `chown <사용자> <파일>` 또는 제거

### U-16 (상) | /etc/passwd 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 644 이하
- **점검**: `ls -l /etc/passwd`
- **조치**: `chown root /etc/passwd && chmod 644 /etc/passwd`

### U-17 (상) | 시스템 시작 스크립트 권한 설정
- **양호**: 소유자가 root/bin/sys/adm 중 하나 + 일반사용자(other) 쓰기 권한 없음
- **점검**: `find /etc/rc.d/rc*.d/ -type l -exec ls -l {} +`
- **조치**: `chown root <파일> && chmod o-w <파일>`

### U-18 (상) | /etc/security/passwd 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 400 이하
- **점검**: `ls -l /etc/security/passwd`
- **조치**: `chown root /etc/security/passwd && chmod 400 /etc/security/passwd`

### U-19 (상) | /etc/hosts 파일 소유자 및 권한 설정
- **양호**: 권한 644 이하
- **점검**: `ls -l /etc/hosts`
- **조치**: `chown root /etc/hosts && chmod 644 /etc/hosts`

### U-20 (상) | /etc/inetd.conf 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 600 이하
- **점검**: `ls -l /etc/inetd.conf`
- **조치**: `chown root /etc/inetd.conf && chmod 600 /etc/inetd.conf`

### U-21 (상) | /etc/syslog.conf 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 640 이하
- **점검**: `ls -l /etc/syslog.conf`
- **조치**: `chown root /etc/syslog.conf && chmod 640 /etc/syslog.conf`

### U-22 (상) | /etc/services 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 644 이하
- **점검**: `ls -l /etc/services`
- **조치**: `chown root /etc/services && chmod 644 /etc/services`

### U-23 (상) | SUID, SGID 설정 파일 점검
- **양호**: 불필요한 SUID/SGID 없음
- **점검**: `find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -ls 2>/dev/null`
- **조치**: `chmod -s <파일>`

### U-24 (상) | 환경변수 파일 권한 설정
- **양호**: 환경변수 설정 파일들의 other 쓰기 권한 없음 + /home/[계정명] 폴더 내 파일 소유자가 [계정명] 또는 root (둘 다 충족)
- **점검**: `ls -la ~/.profile /etc/profile 2>/dev/null`
- **조치**: `chmod o-w <파일>`

### U-25 (상) | world writable 파일 점검
- **양호**: world writable 파일 없거나 인지
- **점검**: `find / -type f -perm -2 -ls 2>/dev/null`
- **조치**: `chmod o-w <파일>`

### U-26 (상) | /dev에 존재하지 않는 device 파일 점검
- **양호**: /dev에 불필요 일반 파일 없음
- **점검**: `find /dev -type f -ls 2>/dev/null`
- **조치**: `rm <파일>`

### U-27 (상) | $HOME/.rhosts, hosts.equiv 사용 금지
- **양호**: r-command 미사용 또는 권한 600·`+` 없음
- **점검**: `cat /etc/hosts.equiv 2>/dev/null`; `find /home -name ".rhosts" 2>/dev/null`
- **조치**: 파일 삭제 또는 `chmod 600`; `+` 제거

### U-28 (상) | 접속 IP 및 포트 제한
- **양호**: IP/포트 제한 설정
- **점검**:
  - TCP Wrapper: `cat /etc/hosts.deny /etc/hosts.allow 2>/dev/null`
  - IPFilter: `cat /etc/ipf/ipf.conf 2>/dev/null`
- **조치**: `/etc/hosts.deny` → `ALL:ALL`; `/etc/hosts.allow`에 허용 IP

### U-29 (하) | hosts.lpd 파일 소유자 및 권한 설정
- **양호**: 파일 없거나 root 소유·권한 600 이하
- **점검**: `ls -l /etc/hosts.lpd 2>/dev/null`
- **조치**: `chown root /etc/hosts.lpd && chmod 600 /etc/hosts.lpd`

### U-30 (중) | UMASK 설정 관리
- **양호**: UMASK 022 이상
- **점검**: `grep -i umask /etc/profile`; `grep umask /etc/security/user | head -5`; `umask`
- **조치**: `/etc/profile`에 `umask 022`; `/etc/security/user` default → `umask = 022`

### U-31 (중) | 홈디렉토리 소유자 및 권한 설정
- **양호**: 홈 디렉터리에 other 쓰기 권한 없음 (o-w)
- **취약**: other 쓰기 권한 있음 (디렉터리 권한 문자열의 9번째 자리에 `w` 존재, 예: `drwxrwxrwx`)
- **점검**: `awk -F: '{print $6}' /etc/passwd | xargs -I{} ls -ld {} 2>/dev/null`
- **조치**: `chmod o-w <홈디렉토리>`

### U-32 (중) | 홈 디렉토리 존재 관리
- **양호**: 홈 디렉토리 미존재 계정 없음
- **점검**: `awk -F: '{print $1,$6}' /etc/passwd` 확인
- **조치**: 불필요 계정 `rmuser` 또는 홈 디렉토리 생성

### U-33 (하) | 숨겨진 파일 및 디렉토리 검색 및 제거
- **양호**: 의심스러운 숨겨진 파일 없음
- **점검**: `find / -name ".*" -ls 2>/dev/null | head -50`
- **조치**: `rm <파일>`

### U-34 (상) | Finger 서비스 비활성화
- **양호**: Finger 비활성화
- **점검**: `grep finger /etc/inetd.conf`
- **조치**: `/etc/inetd.conf`에서 finger 줄 주석 처리; `refresh -s inetd`

### U-35 (상) | 공유 서비스 익명 접근 제한
- **양호**: FTP/NFS/Samba 익명 접근 차단
- **점검**:
  - NFS: `grep anon /etc/exports 2>/dev/null`
  - vsFTP: `grep anonymous_enable /etc/vsftpd.conf 2>/dev/null`
- **조치**: NFS `anon=-1`; vsFTP `anonymous_enable=NO`; `kill -1 <PID>`

### U-36 (상) | r 계열 서비스 비활성화
- **양호**: rlogin, rsh, rexec 비활성화
- **점검**: `grep -E "shell|login|exec" /etc/inetd.conf`
- **조치**: `/etc/inetd.conf`에서 주석 처리; `refresh -s inetd`

### U-37 (상) | crontab 설정파일 권한 설정
- **양호**: /usr/bin/crontab의 other 실행권한 없음 + /usr/bin/at의 other 실행권한 없음 + cron 및 at 관련 파일 권한 640 이하 (3조건 모두 충족)
- **점검**: `ls -l /usr/bin/crontab`; `ls -l /var/spool/cron/crontabs/`; `ls -l /var/adm/cron/`
- **조치**: `chmod 750 /usr/bin/crontab`; cron 관련 파일 `chmod 640`

### U-38 (상) | DoS 공격에 취약한 서비스 비활성화
- **양호**: echo, discard, daytime, chargen 비활성화
- **점검**: `grep -E "echo|discard|daytime|chargen" /etc/inetd.conf`
- **조치**: `/etc/inetd.conf`에서 주석 처리; `refresh -s inetd`

### U-39 (상) | 불필요한 NFS 서비스 비활성화
- **양호**: NFS 서비스 비활성화
- **점검**: `lssrc -a | grep nfs`; `ps -ef | grep nfsd`
- **조치**: `stopsrc -g nfs`; `/etc/rc.nfs` 수정(S60nfs → _S60nfs)

### U-40 (상) | NFS 접근 통제
- **양호**: 접근 통제 설정, 설정 파일 권한 644 이하
- **점검**: `cat /etc/exports`; `ls -l /etc/exports`
- **조치**: `/etc/exports`에 호스트 명시; `chmod 644 /etc/exports`; `exportfs -ra`

### U-41 (상) | 불필요한 automountd 제거
- **양호**: automountd 비활성화
- **점검**: `lssrc -a | grep automountd`; `ps -ef | grep automountd`
- **조치**: `stopsrc -s automountd`; `/etc/inittab` 주석 처리; `init q`

### U-42 (상) | 불필요한 RPC 서비스 비활성화
- **양호**: 다음 RPC 서비스가 **모두 비활성화** (주석 처리 또는 등록 부재)
- **취약**: 다음 중 **하나라도 활성화**되어 있으면 취약
- **점검 대상 서비스 (전체)**: `rexd`, `rstatd`, `rusersd`, `sprayd`, `rwalld`, `rquotad`, `ttdbserver`, `cmsd`
- **점검**: `grep -vE '^[[:space:]]*#' /etc/inetd.conf | grep -E "rexd|rstatd|ruser|spray|wall|rquota|ttdbserver|cmsd"` (주석 제외 매칭)
- **조치**: `/etc/inetd.conf`의 해당 라인 주석 처리 후 `refresh -s inetd` 적용

### U-43 (상) | NIS, NIS+ 점검
- **양호**: NIS 비활성화
- **점검**: `lssrc -a | grep -E "ypserv|ypbind"`
- **조치**: `stopsrc -s ypserv`; `stopsrc -s ypbind`; `/etc/inittab` 주석 처리; `init q`

### U-44 (상) | tftp, talk 서비스 비활성화
- **양호**: tftp, talk, ntalk 비활성화
- **점검**: `grep -E "tftp|talk" /etc/inetd.conf`
- **조치**: `/etc/inetd.conf`에서 주석 처리; `refresh -s inetd`

### U-45 (상) | 메일 서비스 버전 점검
- **양호**: 최신 보안 패치 적용
- **점검**: `sendmail -d0 -bt 2>&1 | head -3`; `lssrc -a | grep sendmail`
- **조치**: `stopsrc -s sendmail`; IBM Fix Central에서 패치 다운로드 후 적용; 미사용 시 `/etc/rc.tcpip` 주석 처리

### U-46 (상) | 일반 사용자의 메일 서비스 실행 방지
- **선결 조건 (점검 대상 판별)**: 메일 데몬이 **실제 구동 중**이어야 점검 대상
  - 양호/취약 판정 대상: `sendmail -bd` (background daemon), 25번 포트 LISTEN 중인 sendmail/postfix master
  - **N/A 처리 케이스**: `sendmail -bt -d0` (address test mode, 버전·설정 확인용 일회성), `sendmail -FCronDaemon` (cron 일회성 호출), `sendmail -q` (큐 처리 일회성), `sendmail -bv` (verify) — 모두 데몬 구동 아님
  - 데몬 미구동 + 25 포트 미LISTEN → **N/A**
- **양호**: (데몬 구동 중일 때) 일반 사용자가 메일 큐 조작 불가 — Sendmail은 `PrivacyOptions`에 `restrictqrun` 명시, Postfix는 `/usr/sbin/postsuper` other 실행권한(o-x) 제거
- **취약**: (데몬 구동 중인데) 위 설정 부재
- **점검**:
  - 데몬 구동 여부: `lssrc -s sendmail | grep active`; `netstat -an | grep '\.25 '`
  - Sendmail 옵션: `grep restrictqrun /etc/mail/sendmail.cf 2>/dev/null`
- **조치**: `PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun`; `stopsrc -s sendmail; startsrc -s sendmail`

### U-47 (상) | 스팸 메일 릴레이 제한
- **양호**: 릴레이 제한 설정
- **점검**: `grep Relaying /etc/mail/sendmail.cf 2>/dev/null`
- **조치**: `/etc/mail/access`에 릴레이 정책; `makemap hash /etc/mail/access.db < /etc/mail/access`

### U-48 (중) | expn, vrfy 명령어 제한
- **양호**: noexpn, novrfy 설정
- **점검**: `grep PrivacyOptions /etc/mail/sendmail.cf 2>/dev/null`
- **조치**: `PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun`

### U-49 (상) | DNS 보안 버전 패치
- **양호**: 최신 BIND 버전 또는 미사용
- **점검**: `named -v 2>/dev/null`; `lssrc -a | grep named`
- **조치**: `stopsrc -s named`; IBM Fix Central에서 패치 적용

### U-50 (상) | DNS ZoneTransfer 설정
- **양호**: 허가된 호스트에만 Zone Transfer 허용
- **점검**: `grep allow-transfer /etc/named.conf 2>/dev/null`
- **조치**: `allow-transfer { <Secondary IP>; };`

### U-51 (중) | DNS 동적 업데이트 설정 금지
- **양호**: 동적 업데이트 비활성화 또는 접근 통제
- **점검**: `grep allow-update /etc/named.conf 2>/dev/null`
- **조치**: `allow-update { none; };`

### U-52 (중) | Telnet 서비스 비활성화
- **양호**: Telnet 비활성화
- **점검**: `grep telnet /etc/inetd.conf`
- **조치**: `/etc/inetd.conf`에서 telnet 주석 처리; `refresh -s inetd`; `startsrc -s sshd`

### U-53 (하) | FTP 서비스 정보 노출 제한
- **양호**: FTP 배너 정보 미노출
- **점검**: `dspcat -g /usr/lib/nls/msg/en_US/ftpd.cat 2>/dev/null | grep FTP`
- **조치**: 메시지 카탈로그에서 배너 변경; `gencat /usr/lib/nls/msg/en_US/ftpd.cat /tmp/ftpd.msg`

### U-54 (중) | 암호화되지 않는 FTP 서비스 비활성화
- **양호**: 평문 FTP 비활성화
- **점검**: `grep ftp /etc/inetd.conf`; `lssrc -a | grep ftp`
- **조치**: `/etc/inetd.conf`에서 ftp 주석 처리; `refresh -s inetd`

### U-55 (중) | FTP 계정 shell 제한
- **양호**: ftp 계정에 /bin/false
- **점검**: `grep "^ftp:" /etc/passwd`
- **조치**: `chuser shell=/bin/false ftp`

### U-56 (하) | FTP 서비스 접근 제어 설정
- **양호**: 특정 IP/호스트만 FTP 접근
- **점검**: `cat /etc/ftpusers 2>/dev/null`; TCP Wrapper 설정 확인
- **조치**: `/etc/ftpusers`에 차단 사용자 등록; TCP Wrapper 설정

### U-57 (중) | Ftpusers 파일 설정 (root 접근 차단)
- **양호**: root FTP 접속 차단
- **점검**: `grep root /etc/ftpusers 2>/dev/null`
- **조치**: `/etc/ftpusers`에 root 추가

### U-58 (중) | 불필요한 SNMP 서비스 구동 점검
- **양호**: SNMP 미사용
- **점검**: `lssrc -a | grep snmp`
- **조치**: `stopsrc -s snmpd`; `/etc/rc.tcpip` 주석 처리

### U-59 (상) | 안전한 SNMP 버전 사용
- **양호**: SNMP v3 이상
- **점검**: `grep COMMUNITY /etc/snmpdv3.conf 2>/dev/null`
- **조치**: SNMPv3 설정; v1/v2 COMMUNITY 제거

### U-60 (중) | SNMP Community String 복잡성 설정
- **양호**: public/private 아닌 + **영문+숫자 10자 이상** 또는 **영문+숫자+특수문자 8자 이상**
- **취약**: public/private 사용 OR 위 길이·조합 미충족
- **점검**: `grep COMMUNITY /etc/snmpdv3.conf 2>/dev/null | grep -E "public|private"`
- **조치**: `/etc/snmpdv3.conf`에서 community string 변경 (영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상); `stopsrc -s snmpd; startsrc -s snmpd`

### U-61 (상) | SNMP Access Control 설정
- **양호**: 특정 IP만 SNMP 접근
- **점검**: `grep COMMUNITY /etc/snmpdv3.conf 2>/dev/null`
- **조치**: `COMMUNITY <string> <string> noAuthNoPriv <허용IP> <넷마스크>`

### U-62 (하) | 로그인 시 경고 메시지 설정
- **양호** (다음 **두 조건 모두** 충족):
  1. `/etc/motd` 에 **보안 경고 메시지**가 설정되어 있음 (OS 기본 메시지/welcome 메시지가 아니라 무단접근 경고/책임 명시 등 보안 문구)
  2. `/etc/motd`, `/etc/issue`, `/etc/issue.net` 모두 **OS·버전·커널 정보 노출 없음** (예: `AIX 7.2`, `\v`, `\r`, `\m`, `\s` 같은 escape 시퀀스, `uname` 출력값, 호스트명 노출 금지)
- **취약**: 위 조건 중 하나라도 미충족 — 경고 메시지 미설정/기본 메시지 그대로 OR 어느 파일에라도 OS 정보 노출
- **점검**:
  - `cat /etc/motd`
  - `cat /etc/issue`
  - `cat /etc/issue.net 2>/dev/null`
  - `grep herald /etc/security/login.cfg 2>/dev/null`
  - SSH: `grep Banner /etc/ssh/sshd_config`
- **조치**: `/etc/motd` 에 무단접근 경고 메시지 입력; `/etc/issue`, `/etc/issue.net` 에서 OS·커널 정보 escape 시퀀스 제거 후 동일 경고 메시지로 대체; `/etc/security/login.cfg` → `herald=<경고메시지>`; SSH `Banner /etc/issue.net` 설정

### U-63 (중) | sudo 명령어 접근 관리
- **양호**: /etc/sudoers root 소유, 권한 640 이하
- **점검**: `ls -l /etc/sudoers 2>/dev/null`
- **조치**: `chown root /etc/sudoers && chmod 640 /etc/sudoers`

### U-64 (상) | 주기적 보안 패치 및 벤더 권고사항 적용
- **양호**: 패치 정책 수립 및 주기적 적용
- **점검**:
  - `oslevel -s` (현재 ML/SP 수준)
  - `instfix -i | grep ML; instfix -i | grep SP`
  - IBM Fix Central에서 최신 패치 확인
- **조치**: IBM Fix Central에서 패치 다운로드; `smitty installp`로 적용

### U-65 (중) | NTP 및 시각 동기화 설정
- **양호**: 아래 **두 조건 모두** 충족 시 양호
  1. xntpd 데몬 실행 중 (`lssrc -s xntpd` = active 또는 `ps -ef | grep xntpd` 프로세스 존재)
  2. 상위 NTP 서버와 동기화 완료 — `ntpq -pn` 결과에 **peer 앞 `*` 마크** 존재
- **취약**: 데몬 미실행, 또는 `ntpq -pn` 에서 `*` 마크 없음 (상위 서버 동기화 실패), 또는 모든 peer 의 stratum 이 16
- **참고**: 스크립트 출력 헤더의 "수동 점검 필요" 문구는 점검 스크립트 기본 템플릿일 뿐 — 실제 데이터(프로세스 + ntpq 결과) 로 판단
- **점검**: `ntpq -pn`; `grep server /etc/ntp.conf`; `lssrc -a | grep xntpd`
- **조치**: `/etc/ntp.conf`에 NTP 서버; `startsrc -s xntpd`; `/etc/rc.tcpip`에 활성화

### U-66 (중) | 정책에 따른 시스템 로깅 설정
- **양호**: `/etc/syslog.conf` 에 아래 **8개 selector 가 모두** 설정되어야 양호
  | # | selector | 권장 destination |
  |---|----------|-----------------|
  | 1 | `*.emerg` | `*` |
  | 2 | `*.alert` | `/dev/console` |
  | 3 | `*.alert` | `/var/adm/alert.log` |
  | 4 | `*.err` | `/var/adm/error.log` |
  | 5 | `mail.info` | `/var/adm/mail.log` |
  | 6 | `auth.info` | `/var/adm/auth.log` |
  | 7 | `daemon.info` | `/var/adm/daemon.log` |
  | 8 | `*.emerg;*.alert;*.crit;*.err;*.warning;*.notice;*.info` | `/var/adm/messages` |
- **취약**: 위 selector 중 **하나라도 누락**되면 취약 (예: `*.alert /dev/console` 또는 `*.alert /var/adm/alert.log` 미설정 → 취약)
- **점검**: `lssrc -a | grep syslogd`; `grep -E '\*\.emerg|\*\.alert|\*\.err|mail\.info|auth\.info|daemon\.info' /etc/syslog.conf`
- **조치**: 누락된 selector 추가 후 `refresh -s syslogd`

### U-67 (중) | 로그 디렉터리 소유자 및 권한 설정
- **양호**:
  - 로그 파일 소유자가 root/bin/adm/sys 중 하나 **AND**
  - 권한 644 이하
  - **예외**: `lastlog`, `wtmp`, `btmp` 파일은 권한 **664 이하**까지 양호 인정
    > ※ btmp, wtmp, lastlog 파일은 시스템 관리자나 특정 그룹에게는 읽기 권한을 주어야 하며, 동시에 로그 데이터를 다른 사용자와 공유해야 할 수 있기 때문에 664 설정
- **점검**: `ls -l /var/adm/*.log /var/adm/messages /var/adm/{wtmp,btmp,lastlog} 2>/dev/null`
- **조치**: `chown root /var/adm/<파일> && chmod 640 /var/adm/<파일>` (lastlog/wtmp/btmp 는 664 까지 허용)
