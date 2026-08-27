# dsgoaccount

DS-GO의 계정, SSO, OAuth 2.0 자격 증명을 관리하는 Express 서버입니다. DS-GO가 제공하는 OAuth Client secret, authorization code, access token은 Firestore에 SHA-256 digest만 저장하며, callback URL은 앱에 등록된 값과 완전히 일치해야 합니다.

외부 간편 로그인은 Bytenode와 오량인을 지원합니다. 오량인의 Service Key와 Service Secret은 클라이언트 코드나 Git에 넣지 말고 배포 환경변수 `ORYA_SERVICE_KEY`, `ORYA_SERVICE_SECRET`에만 저장하세요. 오량인 앱에 등록할 callback URL은 `https://dsgoaccount.vercel.app/api/auth/orya/callback`입니다.

## 로컬 실행

`.env.example`을 참고해 `.env.local`을 작성한 뒤 실행합니다.

```bash
npm install
npm run dev
```

[http://localhost:3000](http://localhost:3000)에서 확인할 수 있습니다.

## 오량인 OAuth 흐름

1. 서버가 오량인에 등록된 callback URL과 서버 전용 자격 증명을 보내 일회용 인증 URL을 발급받습니다.
2. 브라우저를 오량인 인증 화면으로 이동하고, 반환되는 state를 서명된 HttpOnly 쿠키와 대조합니다.
3. callback 서버가 5분짜리 일회용 state를 오량인에 검증한 뒤 로그인·회원가입·계정 연결을 처리합니다.

회원가입 시 이용약관과 필수 개인정보 수집·이용 동의가 필요합니다. 오량인이 반환한 원본 state나 Secret은 로그 또는 사용자 데이터에 저장하지 않습니다.
