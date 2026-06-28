# Create Neon Backend

This backend connects the `create-neon` frontend to a local PostgreSQL database.

## 1. Install dependencies

```powershell
npm install
```

## 2. Create `.env`

Copy `.env.example` to `.env` and set your real PostgreSQL password:

```env
PORT=4000
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/createneon_local
CORS_ORIGIN=http://localhost:5173
```

## 3. Create the database in pgAdmin

Create a database named `createneon_local`, then run `db/schema.sql` in the Query Tool.

## 4. Seed an admin user

```powershell
npm run seed:admin -- admin your_password_here
```

## 5. Start the backend

```powershell
npm run dev
```

The frontend already calls `http://localhost:4000/api/auth/login` by default.
