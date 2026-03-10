import { auth } from "@/lib/auth";
import arcjet, {
  type ArcjetDecision,
  type BotOptions,
  type EmailOptions,
  type ProtectSignupOptions,
  type SlidingWindowRateLimitOptions,
  detectBot,
  protectSignup,
  slidingWindow,
} from "@arcjet/next";
import { toNextJsHandler } from "better-auth/next-js";
import { NextRequest } from "next/server";

const aj = arcjet({
  key: process.env.ARCJET_KEY!,
  rules: [],
});

//1. ป้องกันการสมัครด้วยอีเมลที่ไม่พึงประสงค์ในโหมดใช้งานจริง (LIVE) โดยจะบล็อก
const emailOptions = {
  mode: "LIVE",
  deny: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS"], //อีเมลแบบใช้แล้วทิ้ง รูปแบบอีเมลไม่ถูกต้อง โดเมนอีเมลนั้นไม่มีอยู่จริงหรือรับอีเมลไม่ได้
} satisfies EmailOptions;

//2. ป้องกันบอทเข้ามาก่อกวนระบบ
const botOptions = {
  mode: "LIVE",
  allow: [], //หมายถึงไม่อนุญาตให้บอทใดๆ ผ่านเข้ามาได้เลย
} satisfies BotOptions;

//3. จำกัดจำนวนการเรียก API
const rateLimitOptions = {
  mode: "LIVE",
  interval: "2m", //โดยกำหนดให้เรียกได้สูงสุด 5 ครั้ง ภายใน 2 นาที ต่อ 1 ผู้ใช้งาน
  max: 5,
} satisfies SlidingWindowRateLimitOptions<[]>;

//นำกฎทั้ง 3 ข้อด้านบนมัดรวมกันเป็นแพ็กเกจเดียว เพื่อเอาไว้ใช้สำหรับหน้า "สมัครสมาชิก" โดยเฉพาะ
const signupOptions = {
  email: emailOptions,
  bots: botOptions,
  rateLimit: rateLimitOptions,
} satisfies ProtectSignupOptions<[]>;

async function protect(req: NextRequest): Promise<ArcjetDecision> {
  const session = await auth.api.getSession({
    headers: req.headers,
  });

  if (req.nextUrl.pathname.startsWith("/api/auth/sign-up")) {
    const body = await req.clone().json();

    if (typeof body.email === "string") {
      return aj
        .withRule(protectSignup(signupOptions))
        .protect(req, { email: body.email });
    } else {
      return aj
        .withRule(detectBot(botOptions))
        .withRule(slidingWindow(rateLimitOptions))
        .protect(req);
    }
  } else {
    return aj.withRule(detectBot(botOptions)).protect(req);
  }
}

const authHandles = toNextJsHandler(auth.handler);

export const { GET } = authHandles;

export const POST = async (req: NextRequest) => {
  const decision = await protect(req);

  console.log("Arcjet Decision:", decision);

  if (decision.isDenied()) {
    if (decision.reason.isRateLimit()) {
      return new Response(null, { status: 429 });
    } else if (decision.reason.isEmail()) {
      let message: string;

      if (decision.reason.emailTypes.includes("INVALID")) {
        message = "Email address format is invalid. Is there a typo?";
      } else if (decision.reason.emailTypes.includes("DISPOSABLE")) {
        message = "We do not allow disposable email addresses.";
      } else if (decision.reason.emailTypes.includes("NO_MX_RECORDS")) {
        message =
          "Your email domain does not have an MX record. Is there a typo?";
      } else {
        message = "Invalid email.";
      }

      return Response.json({ message }, { status: 400 });
    } else {
      return new Response(null, { status: 403 });
    }
  }

  return authHandles.POST(req);
};
