const express = require('express');

const viewController = require('../controllers/viewsController');
const authController = require('../controllers/authController');

const router = express.Router();

router.use(authController.isLoggedIn);
router.get('/', viewController.getOverView);
router.get('/tour/:slug', viewController.getTour);

router.get('/login', viewController.getLoginForm);
module.exports = router;
