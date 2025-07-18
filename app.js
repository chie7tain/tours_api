const express = require('express');
const path = require('path');

const rateLimit = require('express-rate-limit');

const mongoSanitize = require('express-mongo-sanitize');

const xss = require('xss-clean');
const helmet = require('helmet');
const hpp = require('hpp');

const morgan = require('morgan');

const AppError = require('./utils/appError');

const globalErroHandler = require('./controllers/errorController');

const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');

const app = express();

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));
// 1 GLOBAL MIDDLEWARES
// Serving static files
app.use(express.static(path.join(__dirname, 'public')));
// Set security HTTP headers
app.use(helmet());

// development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit requests from same API
const limiter = rateLimit({
  max: 100,
  windowsMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!',
});

app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitize
app.use(xss());
// Prevent parameter pollution
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsQuantity',
      'ratingsAverage',
      'maxGroupSize',
      'difficulty',
      'price',
    ],
  }),
);

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

app.get('/', (req, res) => {
  res.status(200).render('base', {
    tour: 'Testing',
    user: 'Ikechukuw',
  });
});
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`));
});

app.use(globalErroHandler);
module.exports = app;
