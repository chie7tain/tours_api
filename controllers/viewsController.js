const Tour = require('../models/tourModel');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');

exports.getOverView = catchAsync(async (req, res) => {
  const tours = await Tour.find();

  res.status(200).render('overview', {
    title: 'All Tours',
    tours,
  });
});

exports.getTour = catchAsync(async (req, res, next) => {
  const tour = await Tour.findOne({ slug: req.params.slug }).populate({
    path: 'reviews',
    fields: 'review rating user',
  });

  res.status(200).render('tour', {
    title: ` ${tour.name} Tour`,
    tour,
    locations: JSON.stringify(tour.locations),
  });
});

exports.getLoginForm = catchAsync(async (req, res) => {
  console.log(req.body);
  res.status(200).render('login', {
    title: 'Log into your account',
  });
});
