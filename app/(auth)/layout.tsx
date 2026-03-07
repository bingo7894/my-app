import { buttonVariants } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react"; // เอา Link ออกจากตรงนี้นะครับ
import Image from "next/image";
import Link from "next/link"; // ต้องนำเข้า Link จาก next/link เท่านั้น!
import { ReactNode } from "react";
import Logo from "../../public/Logo.jpg";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex min-h-svh flex-col items-center justify-center p-4">
      <Link
        href="/"
        className={buttonVariants({
          variant: "outline",
          className: "absolute left-4 top-4 md:left-8 md:top-8",
        })}
      >
        <ArrowLeft className="mr-2 size-4" />
        Back
      </Link>

      <div className="flex w-full max-w-sm flex-col gap-6">
        <Link
          className="flex items-center gap-2 self-center font-medium"
          href="/"
        >
          <Image src={Logo} alt="Logo" width={128} height={128} />
        </Link>
        {children}

        <div className="text-center text-xs text-muted-foreground">
          By clicking continue, you agree to our
          <br />
          <span className="hover:text-primary hover:underline cursor-pointer">
            Terms of Service
          </span>{" "}
          and Privacy Policy
        </div>
      </div>
    </div>
  );
}
