import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "./generated/client.ts";

const client = new PrismaClient({
  adapter: new PrismaPg({
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT),
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    ssl: false,
  }),
});

try {
  const rows = await client.$queryRaw<Array<{ u: string }>>`select current_user as u`;
  console.log(rows[0].u);
} finally {
  await client.$disconnect();
}
