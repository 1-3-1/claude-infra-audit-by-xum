# Unix 점검 기준 — Solaris

## 기본 경로 및 명령어
| 항목 | 경로/명령 |
|------|---------|
| 서비스 관리 | `svcadm enable/disable`, `svcs -a` |
| inetd 서비스 | `inetadm -d <서비스>`, `inetadm \| grep` |
| 패키지 관리 | `pkg list`, `pkg update` (Solaris 11) |
| 비밀번호 정책 | `/etc/default/passwd`, `/etc/security/policy.conf` |
| Shadow 파일 | `/etc/shadow` |
| 계정 잠금 | `/etc/security/policy.conf` (LOCK_AFTER_RETRIES) |
| 로그 파일 | `/var/log/` (Solaris 11), `/var/adm/` |
| NTP | `/etc/ntp.conf`, `ntpq -pn` |
| 버전 확인 | `uname -a`, `cat /etc/release` |
| 방화벽 | Packet Filter (`/etc/firewall/pf.conf`), TCP Wrapper |

---

## ⚠️ 점검 기준 참조 규칙 (필수)

이 파일의 점검 항목(U-01 ~ U-67)을 평가할 때 — 직접 평가하든, 서브에이전트에게 위임하든 — 다음을 반드시 지킨다:

1. **기준은 이 파일을 Read 도구로 직접 읽어 확인**한다. 기억·이전 대화 요약·컴팩트 summary에서 기준을 가져오지 않는다 (요약은 손실 압축이므로 selector·임계값·예외조건이 변형될 수 있음).
2. 서브에이전트에게 위임할 때는 기준을 프롬프트에 인라인으로 박지 말고, **다음과 같이 지시**한다:
   > "판단 기준은 `unix/solaris/CLAUDE.md`의 U-XX 섹션을 Read 도구로 읽어 그대로 적용하라. 요약·재해석·축약 금지. 명시된 selector/조건이 하나라도 누락되면 취약으로 판정."
3. 점검 결과 받은 뒤 이중검토 단계에서 양호 판정 1~2건을 샘플링해 이 파일의 기준과 직접 대조한다. 기준 미스매치 발견 시 해당 코드(전체) 재점검을 즉시 트리거한다.

---

## 점검 항목 (U-01 ~ U-67)

### U-01 (상) | root 계정 원격 접속 제한
- **양호**: `/etc/ssh/sshd_config` 에 **`PermitRootLogin no` 가 명시 설정**되어 있어야 양호 (주석 처리된 `#PermitRootLogin no` 는 OpenSSH 기본값에 의존하므로 **취약**)
- **취약**: `PermitRootLogin yes` OR `PermitRootLogin` 라인이 주석 처리되어 있거나 부재 (명시 설정 없음 → 기본값 의존 → 취약)
- **점검**:
  - SSH: `grep -E "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config` (주석 제외 매칭)
  - Telnet: `grep CONSOLE /etc/default/login`
- **조치**: `/etc/ssh/sshd_config` 의 `#PermitRootLogin` 주석 제거 후 `PermitRootLogin no` 로 명시; `/etc/default/login` → `CONSOLE=/dev/console`; sshd 재시작

### U-02 (상) | 비밀번호 관리정책 설정
- **양호**: 영문/숫자/특수문자 포함 + 최소 8자 이상 + 최소 사용기간 1일 + 최대 사용기간 90일 + 비밀번호 기억 4회 이상 (5조건 모두 충족)
- **점검**: `grep -E "PASSLENGTH|MINDIGIT|MINUPPER|MAXDAYS|MINDAYS" /etc/default/passwd`
- **조치**: `/etc/default/passwd` 설정:
  ```
  PASSLENGTH=8
  MINDIGIT=1
  MINUPPER=1
  MINLOWER=1
  MINSPECIAL=1
  MAXDAYS=90
  MINDAYS=1
  ```

### U-03 (상) | 계정 잠금 임계값 설정
- **양호**: 임계값 10회 이하
- **점검**:
  - Solaris 5.9 미만: `grep RETRIES /etc/default/login`
  - Solaris 5.9 이상: `grep LOCK_AFTER_RETRIES /etc/security/policy.conf`
- **조치**: `/etc/security/policy.conf` → `LOCK_AFTER_RETRIES=YES`; `/etc/default/login` → `RETRIES=10`

### U-04 (상) | 비밀번호 파일 보호
- **양호**: shadow 비밀번호 사용
- **점검**: `awk -F: '{print $2}' /etc/passwd | grep -v '^[x*!]'`
- **조치**: `pwconv`

### U-05 (상) | root 이외의 UID '0' 금지
- **양호**: UID=0이 root만
- **점검**: `awk -F: '($3==0)' /etc/passwd`
- **조치**: `usermod -u <새UID> <계정명>`

### U-06 (상) | 사용자 계정 su 기능 제한
- **양호**: wheel 그룹만 su 사용
- **점검**: `ls -l /usr/bin/su`; `grep wheel /etc/group`
- **조치**: `groupadd wheel`; `chgrp wheel /usr/bin/su`; `chmod 4750 /usr/bin/su`; `usermod -G wheel <계정>`

### U-07 (하) | 불필요한 계정 제거
- **양호**: 불필요한 계정 없음
- **점검**: `cat /etc/passwd`; `last | head -20`
- **조치**: `userdel <계정명>`

### U-08 (중) | 관리자 그룹에 최소한의 계정 포함
- **양호**: root 그룹에 불필요 계정 없음
- **점검**: `grep "^root:" /etc/group`
- **조치**: `gpasswd -d <사용자> root`

### U-09 (하) | 계정이 존재하지 않는 GID 금지
- **양호**: **GID >= 999** 인 그룹 중 구성원이 없는 그룹이 존재하지 않음
- **취약**: **GID >= 999** 인 그룹 중 구성원이 없는 그룹이 1개 이상 존재
- **N/A**: GID < 999 (시스템 그룹) — 임의 화이트리스트 판단 금지, **GID 값으로만** 점검 대상 결정
- **점검**: `awk -F: '$3 >= 999 && $4 == "" {print $1, $3}' /etc/group`
- **조치**: `groupdel <그룹명>` (GID >= 999 빈 그룹만 대상)

### U-10 (중) | 동일한 UID 금지
- **양호**: 중복 UID 없음
- **점검**: `awk -F: '{print $3}' /etc/passwd | sort | uniq -d`
- **조치**: `usermod -u <새UID> <계정명>`

### U-11 (하) | 사용자 shell 점검
- **양호**: 불필요 계정에 `/bin/false`
- **점검**: `awk -F: '($7 != "/bin/false")' /etc/passwd` (daemon, bin, sys, adm 등 확인)
- **조치**: `usermod -s /bin/false <계정명>`

### U-12 (하) | 세션 종료 시간 설정
- **양호**: TMOUT 600초 이하
- **점검**: `grep TMOUT /etc/profile`
- **조치**: `/etc/profile`에 `TMOUT=600; export TMOUT`

### U-13 (중) | 안전한 비밀번호 암호화 알고리즘 사용
- **양호**: SHA-256 또는 SHA-512
- **점검**: `grep CRYPT_DEFAULT /etc/security/policy.conf`; `head -1 /etc/shadow | awk -F: '{print substr($2,1,3)}'`
- **조치**: `/etc/security/policy.conf` → `CRYPT_DEFAULT=6` (SHA-512) 또는 `CRYPT_DEFAULT=5` (SHA-256)

### U-14 (상) | root 홈·PATH 설정
- **양호**: PATH에 `.` 없음
- **점검**: `echo $PATH | grep -E "(^|:)\.(:|$)"`
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
- **점검**: `ls -al $(readlink -f /etc/rc*.d/ | sed 's/$/*/')`
- **조치**: `chown root <파일> && chmod o-w <파일>`

### U-18 (상) | /etc/shadow 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 400 이하
- **점검**: `ls -l /etc/shadow`
- **조치**: `chown root /etc/shadow && chmod 400 /etc/shadow`

### U-19 (상) | /etc/hosts 파일 소유자 및 권한 설정
- **양호**: 권한 644 이하
- **점검**: `ls -l /etc/hosts`
- **조치**: `chown root /etc/hosts && chmod 644 /etc/hosts`

### U-20 (상) | /etc/inetd.conf 파일 소유자 및 권한 설정
- **양호**: root 소유, 권한 600 이하
- **점검**: `ls -l /etc/inetd.conf 2>/dev/null`
- **조치**: `chown root /etc/inetd.conf && chmod 600 /etc/inetd.conf`

### U-21 (상) | /etc/syslog.conf 파일 소유자 및 권한 설정
- **양호**: root(또는 bin, sys) 소유, 권한 640 이하
- **점검**:
  - syslog: `ls -l /etc/syslog.conf 2>/dev/null`
  - rsyslog: `ls -l /etc/rsyslog.conf 2>/dev/null`
- **조치**: `chown root /etc/syslog.conf && chmod 640 /etc/syslog.conf`

### U-22 (상) | /etc/services 파일 소유자 및 권한 설정
- **양호**: root(또는 bin, sys) 소유, 권한 644 이하
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
- **점검**: `cat /etc/hosts.equiv 2>/dev/null`; `find /export/home -name ".rhosts" 2>/dev/null`
- **조치**: 파일 삭제 또는 `chmod 600`; `+` 제거

### U-28 (상) | 접속 IP 및 포트 제한
- **양호**: IP/포트 제한 설정
- **점검**:
  - TCP Wrapper: `cat /etc/hosts.deny /etc/hosts.allow 2>/dev/null`
  - Packet Filter: `cat /etc/firewall/pf.conf 2>/dev/null`
- **조치**: TCP Wrapper `/etc/hosts.deny` → `ALL:ALL`; `/etc/hosts.allow`에 허용 IP

### U-29 (하) | hosts.lpd 파일 소유자 및 권한 설정
- **양호**: 파일 없거나 root 소유·권한 600 이하
- **점검**: `ls -l /etc/hosts.lpd 2>/dev/null`
- **조치**: `chown root /etc/hosts.lpd && chmod 600 /etc/hosts.lpd`

### U-30 (중) | UMASK 설정 관리
- **양호**: UMASK 022 이상
- **점검**: `grep -i umask /etc/profile /etc/default/login 2>/dev/null`; `umask`
- **조치**: `/etc/profile`에 `umask 022`; `/etc/default/login` → `UMASK=022`

### U-31 (중) | 홈디렉토리 소유자 및 권한 설정
- **양호**: 홈 디렉터리에 other 쓰기 권한 없음 (o-w)
- **취약**: other 쓰기 권한 있음 (디렉터리 권한 문자열의 9번째 자리에 `w` 존재, 예: `drwxrwxrwx`)
- **점검**: `awk -F: '{print $6}' /etc/passwd | xargs -I{} ls -ld {} 2>/dev/null`
- **조치**: `chmod o-w <홈디렉토리>`

### U-32 (중) | 홈 디렉토리 존재 관리
- **양호**: 홈 디렉토리 미존재 계정 없음
- **점검**: `awk -F: '{print $1,$6}' /etc/passwd` 확인 후 디렉토리 존재 여부
- **조치**: 불필요 계정 삭제 또는 홈 디렉토리 생성

### U-33 (하) | 숨겨진 파일 및 디렉토리 검색 및 제거
- **양호**: 의심스러운 숨겨진 파일 없음
- **점검**: `find / -name ".*" -ls 2>/dev/null | head -50`
- **조치**: `rm <파일>`

### U-34 (상) | Finger 서비스 비활성화
- **양호**: Finger 비활성화
- **점검**:
  - Solaris 5.10+: `inetadm | grep finger`
  - Solaris 5.9 이하: `grep finger /etc/inetd.conf`
- **조치**: Solaris 5.10+: `inetadm -d svc:/network/finger:default`; Solaris 5.9-: 주석 처리

### U-35 (상) | 공유 서비스 익명 접근 제한
- **양호**: FTP/NFS/Samba 익명 접근 차단
- **점검**:
  - NFS: `grep anon /etc/dfs/dfstab 2>/dev/null`
  - vsFTP: `grep anonymous_enable /etc/vsftpd.conf 2>/dev/null`
- **조치**: NFS `anon=-1`; vsFTP `anonymous_enable=NO`

### U-36 (상) | r 계열 서비스 비활성화
- **양호**: rlogin, rsh, rexec 비활성화
- **점검**:
  - Solaris 5.10+: `inetadm | egrep "shell|rlogin|rexec"`
  - Solaris 5.9-: `grep -E "shell|login|exec" /etc/inetd.conf`
- **조치**: Solaris 5.10+: `inetadm -d <서비스>`; Solaris 5.9-: `/etc/inetd.conf` 주석 처리

### U-37 (상) | crontab 설정파일 권한 설정
- **양호**: /usr/bin/crontab의 other 실행권한 없음 + /usr/bin/at의 other 실행권한 없음 + cron 및 at 관련 파일 권한 640 이하 (3조건 모두 충족)
- **점검**: `ls -l /usr/bin/crontab`; `ls -l /var/spool/cron/crontabs/`; `ls -l /etc/cron.d/`
- **조치**: `chmod 750 /usr/bin/crontab`; cron 관련 파일 `chmod 640`

### U-38 (상) | DoS 공격에 취약한 서비스 비활성화
- **양호**: echo, discard, daytime, chargen 비활성화
- **점검**: `inetadm | grep enable | egrep "echo|discard|daytime|chargen"`
- **조치**: `inetadm -d <서비스>`

### U-39 (상) | 불필요한 NFS 서비스 비활성화
- **양호**: NFS 서비스 비활성화
- **점검**: `inetadm | egrep "nfs|statd|lockd"`; `svcs -a | grep nfs`
- **조치**: `inetadm -d <서비스>`; `svcadm disable nfs/server`

### U-40 (상) | NFS 접근 통제
- **양호**: 접근 통제 설정, 설정 파일 권한 644 이하
- **점검**: `cat /etc/dfs/dfstab 2>/dev/null`; `ls -l /etc/dfs/dfstab`
- **조치**: `/etc/dfs/dfstab`에 호스트 명시; `chmod 644 /etc/dfs/dfstab`; `shareall`

### U-41 (상) | 불필요한 automountd 제거
- **양호**: autofs 비활성화
- **점검**: `svcs -a | grep autofs`
- **조치**: `svcadm disable svc:/system/filesystem/autofs:default`

### U-42 (상) | 불필요한 RPC 서비스 비활성화
- **양호**: 다음 RPC 서비스가 **모두 비활성화**
- **취약**: 다음 중 **하나라도 enabled** 상태이면 취약
- **점검 대상 서비스 (전체)**: `rpc.rquotad`(rquota), `rpc.ttdbserverd`(ttdbserver), `rpc.cmsd`, `rexd`, `rstatd`(rstart), `rusersd`(rusers), `sprayd`(spray), `rwalld`(wall)
- **점검**: `inetadm | grep enabled | egrep "ttdbserver|rex|rstart|rusers|spray|wall|rquota|cmsd"`; `svcs -a | grep rpc`
- **조치**: `svcadm disable <서비스>` (각 서비스별 적용)

### U-43 (상) | NIS, NIS+ 점검
- **양호**: NIS 비활성화
- **점검**: `svcs -a | grep nis`
- **조치**: `svcadm disable <NIS 서비스>`

### U-44 (상) | tftp, talk 서비스 비활성화
- **양호**: tftp, talk, ntalk 비활성화
- **점검**: `inetadm | egrep "tftp|talk"`
- **조치**: `inetadm -d <서비스>`

### U-45 (상) | 메일 서비스 버전 점검
- **양호**: 최신 보안 패치 적용
- **점검**: `/usr/sbin/sendmail -d0 -bt 2>&1 | head -3`; `svcs -a | grep sendmail`
- **조치**: Solaris 패치 적용; 미사용 시 `svcadm disable sendmail`

### U-46 (상) | 일반 사용자의 메일 서비스 실행 방지
- **선결 조건 (점검 대상 판별)**: 메일 데몬이 **실제 구동 중**이어야 점검 대상
  - 양호/취약 판정 대상: `sendmail -bd` (background daemon, 25 포트 LISTEN)
  - **N/A 처리 케이스**: `sendmail -bt -d0` (address test, 일회성), `sendmail -FCronDaemon` (cron), `sendmail -q`, `sendmail -bv` — 모두 데몬 아님
  - 데몬 미구동 + 25 포트 미LISTEN → **N/A**
- **양호**: (데몬 구동 중일 때) Sendmail `PrivacyOptions`에 `restrictqrun` 명시
- **취약**: (데몬 구동 중인데) 설정 부재
- **점검**:
  - 데몬 구동 여부: `svcs -a | grep sendmail | grep online`; `netstat -an | grep '\.25 '`
  - Sendmail: `grep restrictqrun /etc/mail/sendmail.cf 2>/dev/null`
- **조치**: `PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun`; `svcadm refresh sendmail`

### U-47 (상) | 스팸 메일 릴레이 제한
- **양호**: 릴레이 제한 설정
- **점검**: `grep Relaying /etc/mail/sendmail.cf 2>/dev/null`
- **조치**: `/etc/mail/access`에 릴레이 정책 설정; `makemap hash /etc/mail/access.db < /etc/mail/access`

### U-48 (중) | expn, vrfy 명령어 제한
- **양호**: noexpn, novrfy 설정
- **점검**: `grep PrivacyOptions /etc/mail/sendmail.cf 2>/dev/null`
- **조치**: `PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun`

### U-49 (상) | DNS 보안 버전 패치
- **양호**: 최신 BIND 버전 또는 미사용
- **점검**: `named -v 2>/dev/null`; `svcs -a | grep bind`
- **조치**: `svcadm disable bind`; 패치 적용

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
- **점검**: `svcs -a | grep telnet`
- **조치**: `svcadm disable svc:/network/telnet:default`; `svcadm enable ssh`

### U-53 (하) | FTP 서비스 정보 노출 제한
- **양호**: FTP 배너 정보 미노출
- **점검**: `grep ftpd_banner /etc/vsftpd.conf 2>/dev/null`; vsFTP 사용 시
- **조치**: `ftpd_banner=Welcome`; `svcadm refresh vsftpd`

### U-54 (중) | 암호화되지 않는 FTP 서비스 비활성화
- **양호**: 평문 FTP 비활성화
- **점검**: `svcs -a | grep ftp`; `inetadm | grep ftp`
- **조치**: `svcadm disable vsftpd`; 필요 시 SFTP 사용

### U-55 (중) | FTP 계정 shell 제한
- **양호**: ftp 계정에 /bin/false
- **점검**: `grep "^ftp:" /etc/passwd`
- **조치**: `usermod -s /bin/false ftp`

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
- **점검**:
  - Solaris 5.10+: `svcs -a | grep snmp`
  - Solaris 5.9-: `ps -ef | grep snmp`
- **조치**: `svcadm disable svc:/application/management/snmpd:default`

### U-59 (상) | 안전한 SNMP 버전 사용
- **양호**: SNMP v3 이상
- **점검**: `grep -E "rocommunity|rwcommunity" /etc/net-snmp/snmp/snmpd.conf 2>/dev/null`
- **조치**: SNMPv3 사용자 생성; v1/v2 community 제거

### U-60 (중) | SNMP Community String 복잡성 설정
- **양호**: public/private 아닌 + **영문+숫자 10자 이상** 또는 **영문+숫자+특수문자 8자 이상**
- **취약**: public/private 사용 OR 위 길이·조합 미충족
- **점검**: `grep -E "rocommunity|rwcommunity" /etc/net-snmp/snmp/snmpd.conf 2>/dev/null | grep -E "public|private"`
- **조치**: community string 변경 (영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상); `svcadm refresh net-snmp`

### U-61 (상) | SNMP Access Control 설정
- **양호**: 특정 IP만 SNMP 접근
- **점검**: `grep rocommunity /etc/net-snmp/snmp/snmpd.conf 2>/dev/null`
- **조치**: `rocommunity <string> <허용IP>`

### U-62 (하) | 로그인 시 경고 메시지 설정
- **양호** (다음 **두 조건 모두** 충족):
  1. `/etc/motd` 에 **보안 경고 메시지**가 설정되어 있음 (OS 기본 메시지/welcome 메시지가 아니라 무단접근 경고/책임 명시 등 보안 문구)
  2. `/etc/motd`, `/etc/issue`, `/etc/issue.net` 모두 **OS·버전·커널 정보 노출 없음** (예: `SunOS`, `Solaris`, `\v`, `\r`, `\m`, `\s` 같은 escape 시퀀스, `uname` 출력값, 호스트명 노출 금지)
- **취약**: 위 조건 중 하나라도 미충족 — 경고 메시지 미설정/기본 메시지 그대로 OR 어느 파일에라도 OS 정보 노출
- **점검**:
  - `cat /etc/motd`
  - `cat /etc/issue`
  - `cat /etc/issue.net 2>/dev/null`
  - SSH: `grep Banner /etc/ssh/sshd_config`
- **조치**: `/etc/motd` 에 무단접근 경고 메시지 입력; `/etc/issue`, `/etc/issue.net` 에서 OS·커널 정보 escape 시퀀스 제거 후 동일 경고 메시지로 대체; SSH `Banner /etc/issue.net` 설정 후 `svcadm refresh ssh`

### U-63 (중) | sudo 명령어 접근 관리
- **양호**: /etc/sudoers root 소유, 권한 640 이하
- **점검**: `ls -l /etc/sudoers`
- **조치**: `chown root /etc/sudoers && chmod 640 /etc/sudoers`

### U-64 (상) | 주기적 보안 패치 및 벤더 권고사항 적용
- **양호**: 패치 정책 수립 및 적용
- **점검**:
  - `cat /etc/release`
  - Solaris 11: `pkg list -af entire | head -5`; `pkg list -af entire@latest`
  - EOL 확인: Solaris 10 (2021.01 EOL), Solaris 11.4 (지원 중)
- **조치**: `pkg update --accept`; Oracle support 있는 경우 SRU 적용

### U-65 (중) | NTP 및 시각 동기화 설정
- **양호**: 아래 **두 조건 모두** 충족 시 양호
  1. NTP 데몬 실행 중 (`ntpd` / `xntpd` 프로세스 존재 또는 `svcs ntp` 가 online)
  2. 상위 NTP 서버와 동기화 완료 — `ntpq -pn` 결과에 **peer 앞에 `*` 마크**가 존재 (현재 동기화된 서버)
- **취약**: 데몬 미실행, 또는 `ntpq -pn` 에서 `*` 마크 없음 (상위 서버 동기화 실패), 또는 모든 peer 의 stratum 이 16
- **참고**: 스크립트 출력 헤더의 "수동 점검 필요" 문구는 점검 스크립트 기본 템플릿일 뿐 — 실제 데이터(프로세스 + ntpq 결과) 로 판단
- **점검**: `ntpq -pn`; `grep server /etc/ntp.conf`; `svcs -a | grep ntp`
- **조치**: `/etc/ntp.conf`에 NTP 서버 설정; `svcadm enable ntp`

### U-66 (중) | 정책에 따른 시스템 로깅 설정
- **양호**: syslog 또는 rsyslog 사용 환경에 따라 아래 selector 가 **모두** 설정되어야 양호
  - **legacy syslog** (`/etc/syslog.conf`) — 5개 selector 필수:
    | # | selector | 권장 destination |
    |---|----------|-----------------|
    | 1 | `mail.debug` | `/var/log/mail.log` |
    | 2 | `*.info` | `/var/log/syslog.log` |
    | 3 | `*.alert` | `/var/log/syslog.log` (또는 임의 파일) |
    | 4 | `*.alert` | `/dev/console` (또는 `root`) |
    | 5 | `*.emerg` | `*` |
  - **rsyslog** (`/etc/rsyslog.conf`) — Linux 와 동일하게 6개 selector 필수:
    | # | selector | 권장 destination |
    |---|----------|-----------------|
    | 1 | `*.info;mail.none;authpriv.none;cron.none` | `/var/log/messages` |
    | 2 | `auth,authpriv.*` | `/var/log/secure` |
    | 3 | `mail.*` | `/var/log/maillog` |
    | 4 | `cron.*` | `/var/log/cron` |
    | 5 | `*.alert` | `/dev/console` |
    | 6 | `*.emerg` | `*` |
- **취약**: 사용 중인 syslog/rsyslog 의 selector 중 **하나라도 누락**되면 취약 (예: `*.alert` 누락 → 취약)
- **점검**:
  - syslog: `svcs -a | grep system-log`; `grep -E '\*\.info|\*\.alert|\*\.emerg|mail\.debug' /etc/syslog.conf`
  - rsyslog: `grep -E '\*\.info|auth.*authpriv|mail\.\*|cron\.\*|\*\.alert|\*\.emerg' /etc/rsyslog.conf`
- **조치**:
  - syslog: `svcadm refresh svc:/system/system-log:default`
  - rsyslog: `svcadm refresh svc:/system/system-log:rsyslog`

### U-67 (중) | 로그 디렉터리 소유자 및 권한 설정
- **양호**:
  - 로그 파일 소유자가 root/bin/adm/sys 중 하나 **AND**
  - 권한 644 이하
  - **예외**: `lastlog`, `wtmp`, `btmp`, `wtmpx`, `utmpx` 파일은 권한 **664 이하**까지 양호 인정
    > ※ btmp, wtmp, lastlog 파일은 시스템 관리자나 특정 그룹에게는 읽기 권한을 주어야 하며, 동시에 로그 데이터를 다른 사용자와 공유해야 할 수 있기 때문에 664 설정
- **점검**: `ls -l /var/log/*.log /var/adm/*.log /var/adm/{wtmp,wtmpx,utmpx,lastlog} 2>/dev/null`
- **조치**: `chown root /var/log/<파일> && chmod 640 /var/log/<파일>` (lastlog/wtmp/btmp/wtmpx/utmpx 는 664 까지 허용)
