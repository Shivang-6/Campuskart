🛒 CampusKart

CampusKart is a campus-focused e-commerce platform where students can buy, sell, and exchange items within their university community. From books and notes to gadgets and sports equipment, CampusKart provides a safe and simple way for students to trade on campus.

🚀 Features

👤 User Authentication – Secure login/signup with JWT & Google OAuth.

📦 Product Listings – Post items with images, descriptions, and prices.

📸 Image Uploads – Upload product photos using Cloudinary.

🔍 Search & Filter – Easily find items by name, category, or price.

💬 Messaging System – Chat between buyers & sellers.

🎓 Campus Verified – Transactions limited to students for safety.

🌓 Dark/Light Mode – User-friendly UI with theme toggle.

🛠️ Tech Stack

Frontend: React.js, React Router, TailwindCSS

Backend: Node.js, Express.js

Database: MongoDB

Authentication: JWT, Google OAuth, Passport.js

File Uploads: Multer + Cloudinary

Deployment: Vercel (Frontend), Render(Backend)

📦 Installation

Clone the repository:

git clone https://github.com/Shivang-6/Campuskart.git
cd campuskart


Install dependencies:

npm install


Create a .env file in the backend directory with:

MONGO_URI=your_mongodb_connection
JWT_SECRET=your_jwt_secret
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret


Run the backend:

npm run server


Run the frontend:

npm start

📌 Usage

Sign up or log in (via Email/Google).

Browse marketplace for campus products.

Post your own item with image and details.

Connect with buyers/sellers within campus.

🔮 Future Enhancements

📱 Mobile App (React Native).

💬 Built-in chat system.

💳 Secure payments integration (Stripe/UPI).

🏷️ Categories & advanced filters.

⭐ User ratings & reviews.

🤝 Contributing

Contributions are welcome! Fork the repo and submit a pull request 🚀.
