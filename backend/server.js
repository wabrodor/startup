const app = require('./src/app');
const http = require('http');
require('dotenv').config();
const mongoose = require("mongoose")
const { isDBconnected, connectDB} = require("./src/config/db")



const server = http.createServer(app)
const closeServer = () =>
  new Promise((resolve, reject) => {
    server.close((err) => {
      if (err) return reject(err);
      resolve();
    });
  });

const PORT = process.env.PORT || 5000;


const gracefulShutdown = async () => {
  console.log('\n🛑 Graceful shutdown initiated...');

   const timeout = setTimeout(() => {
    console.error('⏰ Forcefully exiting after 10 seconds...');
    process.exit(1);
  }, 10000);

  try {
    console.log("awaiting active connections to terminate")
    await closeServer();
    console.log('✅ HTTP server closed');

    if (isDBconnected()) {
      await mongoose.connection.close();
      console.log('✅ MongoDB connection closed');
    }
clearTimeout(timeout); 
    process.exit(0);
  } catch (err) {
     clearTimeout(timeout);
    console.error('❌ Error during shutdown:', err);
    process.exit(1);
  }
};

const startServer = async () =>{

  try{
 await connectDB();
 server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
  }catch(err){
console.error('❌ Failed to start server due to:', err.message || err);
    process.exit(1);
  }

}
 
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection:', reason);
  gracefulShutdown();
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  gracefulShutdown();
});

startServer()
