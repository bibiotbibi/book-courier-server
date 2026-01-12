require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const admin = require('firebase-admin')
const port = process.env.PORT || 3000
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString(
  'utf-8'
)
const serviceAccount = JSON.parse(decoded)
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
})

const app = express()

// middleware
app.use(
  cors({
    origin: ["http://localhost:5173", process.env.CLIENT_DOMAIN],
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
)
app.use(express.json())

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(' ')[1]
  // console.log(token)
  if (!token) return res.status(401).send({ message: 'Unauthorized Access!' })
  try {
    const decoded = await admin.auth().verifyIdToken(token)
    req.tokenEmail = decoded.email
    // console.log(decoded)
    next()
  } catch (err) {
    console.log(err)
    return res.status(401).send({ message: 'Unauthorized Access!', err })
  }
}

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true, // Kept strict: true as requested
    deprecationErrors: true,
  },
})
async function run() {
  try {

    const db = client.db('booksDB')
    const booksCollection = db.collection('books')
    const ordersCollection = db.collection('orderd')
    const usersCollection = db.collection('users')
    const sellerRequestsCollection = db.collection('sellerRequests')
    const wishlistCollection = db.collection('wishlist')
    const reviewsCollection = db.collection('reviews') 

    //role middleware
    const verifyADMIN = async (req, res, next) => {
      const email = req.tokenEmail
      const user = await usersCollection.findOne({ email })
      if (user?.role !== 'admin')
        return res.status(403).send({ message: "Admin only Actions!", role: user?.role })

      next()
    }

    const verifySELLER = async (req, res, next) => {
      const email = req.tokenEmail
      const user = await usersCollection.findOne({ email })
      if (user?.role !== 'seller')
        return res.status(403).send({ message: "Seller only Actions!", role: user?.role })

      next()
    }

    // --- STATS ENDPOINT (FIXED) ---
    app.get('/stats', async (req, res) => {
      try {
        // We use aggregation instead of distinct to avoid the Strict Mode error
        const [booksCount, usersCount, ordersCount, citiesAgg] = await Promise.all([
          booksCollection.estimatedDocumentCount(),
          usersCollection.estimatedDocumentCount(),
          ordersCollection.estimatedDocumentCount(),
          usersCollection.aggregate([
            { $group: { _id: "$city" } },
            { $count: "totalCities" }
          ]).toArray()
        ]);

        // Extract count from aggregation result, default to 0
        const citiesCount = citiesAgg.length > 0 ? citiesAgg[0].totalCities : 0;

        res.send({
          books: booksCount,
          users: usersCount,
          orders: ordersCount,
          cities: citiesCount > 0 ? citiesCount : 25, // Fallback to 25 if no cities found
        });
      } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).send({ message: 'Error fetching stats' });
      }
    });
    // -----------------------------------

    //save a book data in db
    app.post('/books', verifyJWT, verifySELLER, async (req, res) => {
      const bookData = req.body

      const finalBookData = {
        ...bookData,
        price: Number(bookData.price),
        quantity: Number(bookData.quantity),
      }

      if (isNaN(finalBookData.price) || isNaN(finalBookData.quantity)) {
        return res.status(400).send({ message: 'Invalid price or quantity' })
      }

      const result = await booksCollection.insertOne(finalBookData)
      res.send(result)
    })


    //get all books from db
    app.get('/books', async (req, res) => {
      const result = await booksCollection.find().toArray()
      res.send(result)
    })


    //get single book by id
    app.get('/books/:id', async (req, res) => {
      const id = req.params.id
      const result = await booksCollection.findOne({ _id: new ObjectId(id) })
      res.send(result)
    })

    //payment endpoint
    app.post('/create-checkout-session', async (req, res) => {
      const paymentInfo = req.body
      // console.log(paymentInfo)

      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: paymentInfo?.name,
                description: paymentInfo?.description,
                images: [paymentInfo?.image],
              },
              unit_amount: paymentInfo?.price * 100,
            },
            quantity: 1,
          },
        ],
        customer_email: paymentInfo?.customer?.email,
        mode: 'payment',
        metadata: {
          bookId: paymentInfo?.bookId,
          customer: paymentInfo?.customer.email,
        },
        success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/book-details/${paymentInfo?.bookId}`,
      })
      res.send({ url: session.url })
    })

    app.post('/payment-success', async (req, res) => {
      const { sessionId } = req.body
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const book = await booksCollection.findOne({
        _id: new ObjectId(session.metadata.bookId)
      })
      const order = await ordersCollection.findOne({
        transactionId: session.payment_intent,
      })

      if (session.status === 'complete' && book && !order) {
        //save data to db
        const orderInfo = {
          bookId: session.metadata.bookId,
          transactionId: session.payment_intent,
          image: book?.image,
          customer: session.metadata.customer,
          status: 'pending',
          author: book.author,
          name: book.name,
          category: book.category,
          quantity: 1,
          price: session.amount_total / 100,
        }
        const result = await ordersCollection.insertOne(orderInfo)
        //update book quantity
        await booksCollection.updateOne(
          {
            _id: new ObjectId(session.metadata.bookId)
          },
          { $inc: { quantity: -1 } }
        )
        return res.send({
          transactionId: session.payment_intent,
          orderId: result.insertedId,
        })
      }
      res.send(res.send({
        transactionId: session.payment_intent,
        orderId: order?._id,
      }))
    })

    //get all orders for a customer by email
    app.get('/my-orders', verifyJWT, async (req, res) => {
      const result = await ordersCollection.find({ customer: req.tokenEmail }).toArray()
      res.send(result)
    })


    //get all orders for a seller by email
    app.get('/manage-orders/:email', verifyJWT, verifySELLER, async (req, res) => {
      const email = req.params.email

      const result = await ordersCollection
        .find({ 'author.email': email })
        .toArray()
      res.send(result)
    })


    //get all books for a seller by email
    app.get('/my-books/:email', verifyJWT,
      verifySELLER, async (req, res) => {
        const email = req.params.email

        const result = await booksCollection
          .find({ 'author.email': email })
          .toArray()
        res.send(result)
      })



    // save or update a user in db
    app.post('/user', async (req, res) => {
      const userData = req.body;

      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      userData.role = 'customer'

      const query = {
        email: userData.email,
      };

      const alreadyExists = await usersCollection.findOne(query);
      // console.log('User Already Exists --->', !!alreadyExists);

      if (alreadyExists) {
        // console.log('Updating user info...');
        const result = await usersCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString(),
          },
        });
        return res.send(result);
      }

      // console.log('Saving new user info...');
      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });


    //get a user's role
    app.get('/user/role', verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail })
      res.send({ role: result?.role })
    })

    //handl become-seller request
    app.post('/become-seller', verifyJWT, async (req, res) => {
      const email = req.tokenEmail
      const alreadyExists = await sellerRequestsCollection.findOne({ email })
      if (alreadyExists) return res
        .status(409)
        .send({ message: 'Already requested, wait..' })


      const result = await sellerRequestsCollection.insertOne({ email })
      res.send(result)
    })

    //get all seller request for admin
    app.get('/seller-request', verifyJWT, verifyADMIN, async (req, res) => {
      const result = await sellerRequestsCollection.find().toArray()
      res.send(result)
    })

    //get all users  for admin
    app.get('/users', verifyJWT, verifyADMIN, async (req, res) => {
      const adminEmail = req.tokenEmail
      const result = await usersCollection.find({ email: { $ne: adminEmail } }).toArray()
      res.send(result)
    })


    //update a user role
    app.patch('/update-role', verifyJWT, verifyADMIN, async (req, res) => {
      const { email, role } = req.body
      const result = await usersCollection.updateOne({ email }, { $set: { role } })
      await sellerRequestsCollection.deleteOne({ email })

      res.send(result)
    })

    // DELETE an order by ID 
    app.delete('/orders/:id', verifyJWT, verifySELLER, async (req, res) => {
      const id = req.params.id;

      try {
        const result = await ordersCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Order not found' });
        }

        res.send({ message: 'Order cancelled successfully' });
      } catch (err) {
        console.log(err);
        res.status(500).send({ message: 'Failed to cancel order', err });
      }
    });







    // Add a book to wishlist
    app.post('/wishlist', verifyJWT, async (req, res) => {
      const book = req.body;
      const email = req.tokenEmail;

      const exists = await wishlistCollection.findOne({ bookId: book._id, userEmail: email });
      if (exists) return res.status(409).send({ message: 'Book already in wishlist' });

      const wishlistItem = {
        bookId: book._id,
        userEmail: email,
        name: book.name,
        image: book.image,
        price: book.price,
        addedAt: new Date(),
      };

      const result = await wishlistCollection.insertOne(wishlistItem);
      res.send(result);
    });

    // Get wishlist for a user
    app.get('/wishlist/:email', verifyJWT, async (req, res) => {
      const email = req.params.email;
      const items = await wishlistCollection
        .find({ userEmail: email })
        .project({ name: 1, image: 1, price: 1 })
        .toArray();
      res.send(items);
    });


    // --- REVIEWS SECTION START ---

    // Post a review (Requires Login)
    app.post('/reviews', verifyJWT, async (req, res) => {
      const reviewData = req.body;
      const userEmail = req.tokenEmail;

      const newReview = {
        bookId: reviewData.bookId,
        bookName: reviewData.bookName,
        userName: reviewData.userName,
        userImage: reviewData.userImage,
        rating: parseInt(reviewData.rating),
        comment: reviewData.comment,
        userEmail: userEmail,
        date: new Date(),
      };

      const result = await reviewsCollection.insertOne(newReview);
      res.send(result);
    });

    // Get all reviews for a specific book (Public access)
    app.get('/reviews', async (req, res) => {
      const bookId = req.query.bookId;
      
      const result = await reviewsCollection
        .find({ bookId: bookId })
        .sort({ date: -1 })
        .toArray();
      
      res.send(result);
    });

    // --- REVIEWS SECTION END ---



    // Send a ping to confirm a successful connection
    await client.db('admin').command({ ping: 1 })
    console.log(
      'Pinged your deployment. You successfully connected to MongoDB!'
    )
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir)

app.get('/', (req, res) => {
  res.send('Hello from Server..')
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})