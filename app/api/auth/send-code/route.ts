import { NextRequest, NextResponse } from "next/server";
import nodemailer from "nodemailer";

// In-memory store: email → { code, expiresAt, attempts }
const codeStore = new Map<string, { code: string; expiresAt: number; attempts: number }>();

// Clean up expired codes every 10 minutes
setInterval(() => {
  const now = Date.now();
  codeStore.forEach((v, k) => { if (v.expiresAt < now) codeStore.delete(k); });
}, 600_000);

const ipMap = new Map<string, { count: number; windowStart: number }>();

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const now = Date.now();
  const entry = ipMap.get(ip) ?? { count: 0, windowStart: now };
  if (now - entry.windowStart > 10 * 60 * 1000) { entry.count = 0; entry.windowStart = now; }
  entry.count++;
  ipMap.set(ip, entry);
  if (entry.count > 5)
    return NextResponse.json({ ok: false, error: "too_many_attempts" }, { status: 429 });

  const body = await req.json().catch(() => ({})) as { email?: string };
  const email = String(body.email ?? "").trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return NextResponse.json({ ok: false, error: "invalid_email" }, { status: 400 });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  codeStore.set(email, { code, expiresAt: now + 15 * 60 * 1000, attempts: 0 });

  const smtpPass = process.env.OUTLOOK_APP_PASSWORD;
  if (!smtpPass) {
    console.log(`[send-code] 이메일: ${email}, 인증코드: ${code}`);
    return NextResponse.json({ ok: true, dev: true });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: "scivillclub@gmail.com", pass: smtpPass },
    });
    await transporter.sendMail({
      from: '"Scivill" <scivillclub@gmail.com>',
      to: email,
      subject: "[Scivill] 이메일 인증 코드",
      html: `<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#09090b;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#09090b;min-height:100vh;">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#0f0f12;border:1px solid #27272a;border-radius:12px;overflow:hidden;">

        <!-- 헤더 / 로고 -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e1b4b 0%,#0f0f12 100%);padding:32px 32px 28px;text-align:center;border-bottom:1px solid #27272a;">
            <div style="display:inline-flex;align-items:center;gap:10px;">
              <div style="width:40px;height:40px;background:linear-gradient(135deg,#6366f1,#818cf8);border-radius:10px;display:flex;align-items:center;justify-content:center;">
                <span style="font-size:22px;font-weight:900;color:#fff;line-height:1;">S</span>
              </div>
              <span style="font-size:24px;font-weight:900;color:#fff;letter-spacing:-0.5px;">Scivill</span>
            </div>
            <p style="margin:12px 0 0;font-size:13px;color:#6366f1;font-weight:600;letter-spacing:0.05em;">SCIENCE · CIVILIZE</p>
          </td>
        </tr>

        <!-- 본문 -->
        <tr>
          <td style="padding:32px;">
            <h1 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#fff;">이메일 인증</h1>
            <p style="margin:0 0 24px;font-size:14px;color:#a1a1aa;line-height:1.6;">
              Scivill 회원가입을 위한 인증 코드를 보내드렸습니다.<br>
              아래 6자리 코드를 인증 입력란에 입력해 주세요.
            </p>

            <!-- 인증 코드 박스 -->
            <div style="background:#18181b;border:2px solid #6366f1;border-radius:10px;padding:24px;text-align:center;margin-bottom:28px;">
              <p style="margin:0 0 8px;font-size:11px;font-weight:700;color:#6366f1;letter-spacing:0.15em;text-transform:uppercase;">인증 코드</p>
              <span style="font-size:40px;font-weight:900;letter-spacing:0.25em;color:#fff;">${code}</span>
            </div>

            <!-- 안내 사항 -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#18181b;border:1px solid #27272a;border-radius:8px;margin-bottom:24px;">
              <tr><td style="padding:16px 20px;">
                <p style="margin:0 0 10px;font-size:12px;font-weight:700;color:#a1a1aa;letter-spacing:0.05em;">📋 안내사항</p>
                <ul style="margin:0;padding:0 0 0 16px;color:#71717a;font-size:12px;line-height:2;">
                  <li>이 코드는 <strong style="color:#a1a1aa;">15분 후 만료</strong>됩니다.</li>
                  <li>코드는 <strong style="color:#a1a1aa;">1회만 사용</strong> 가능합니다.</li>
                  <li>본인이 요청하지 않은 경우 이 이메일을 무시하세요.</li>
                  <li>코드를 타인에게 절대 공유하지 마세요.</li>
                </ul>
              </td></tr>
            </table>

            <div style="background:#1c1400;border:1px solid #78580a;border-radius:8px;padding:14px 16px;margin-bottom:16px;">
              <p style="margin:0;font-size:12px;color:#f59e0b;line-height:1.7;">
                📬 <strong>이 메일이 정크/스팸함에 있나요?</strong><br>
                '정크 메일이 아닙니다' 버튼을 눌러주시면 다음부터 받은편지함으로 옵니다.
              </p>
            </div>
            <p style="margin:0;font-size:13px;color:#52525b;line-height:1.6;">
              문의사항이 있으시면 Scivill 관리자에게 연락해 주세요.
            </p>
          </td>
        </tr>

        <!-- 푸터 -->
        <tr>
          <td style="padding:20px 32px;border-top:1px solid #27272a;text-align:center;">
            <p style="margin:0;font-size:11px;color:#3f3f46;">
              © Scivill. All rights reserved.<br>
              이 이메일은 scivill.vercel.app에서 자동 발송되었습니다.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`,
    });
    return NextResponse.json({ ok: true });
  } catch (e) {
    console.error("[send-code]", e);
    return NextResponse.json({ ok: false, error: "email_send_failed" }, { status: 500 });
  }
}

// Verification endpoint — same file for simplicity
export async function PUT(req: NextRequest) {
  const body = await req.json().catch(() => ({})) as { email?: string; code?: string };
  const email = String(body.email ?? "").trim().toLowerCase();
  const inputCode = String(body.code ?? "").trim();

  if (!email || !inputCode)
    return NextResponse.json({ ok: false, error: "missing_fields" }, { status: 400 });

  const stored = codeStore.get(email);
  if (!stored || stored.expiresAt < Date.now())
    return NextResponse.json({ ok: false, error: "code_expired" }, { status: 400 });

  stored.attempts++;
  if (stored.attempts > 5) {
    codeStore.delete(email);
    return NextResponse.json({ ok: false, error: "too_many_attempts" }, { status: 429 });
  }

  if (stored.code !== inputCode)
    return NextResponse.json({ ok: false, error: "invalid_code" }, { status: 400 });

  codeStore.delete(email);
  return NextResponse.json({ ok: true });
}
