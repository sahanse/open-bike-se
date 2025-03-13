import pg from "pg"

const db = new pg.Client({
    port:process.env.PG_PORT,
    host:process.env.PG_HOST,
    password:process.env.PG_PASSWORD,
    database:process.env.PG_BASE,
    user:process.env.PG_USER
})

export default db;