# Gateway 서버

### 개요
- 주소(local) : http://localhost:8080
- 토큰 검증 및 인가 후 도메인 서비스로 라우팅
- 특정 도메인들의 일부 API(조회용)에 대해서, `permitAll`로 설정되어있습니다.

### 토큰 인증
- 토큰 인증/재발급은 Keycloak에 위임합니다.
- Gateway에서는 인증된 사용자의 토큰을 받아, 헤더에 필요한 정보를 담고 라우팅합니다.

### 라우팅 경로
- `src/resources/application.yml` 파일을 참고해주세요.
