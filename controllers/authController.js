const jwt = require('jsonwebtoken');
const User = require('../models/authSchema');
const bcrypt = require('bcryptjs');

// Generate JWT Token with roles
const generateToken = (userId, roles, primaryRole) => {
  return jwt.sign(
    { 
      userId, 
      roles, 
      primaryRole 
    },
    process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// Generate JWT Token with role and roles
const generateTokenWithRole = (userId, roles, primaryRole, currentRole) => {
  return jwt.sign(
    { 
      userId, 
      roles, 
      primaryRole, 
      currentRole 
    },
    process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// Register new user
const register = async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, walletAddress, role = 'user' } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !password || !walletAddress) {
      return res.status(400).json({
        success: false,
        message: 'All fields including wallet address are required'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Validate wallet address format
    const walletRegex = /^0x[a-fA-F0-9]{40}$/;
    if (!walletRegex.test(walletAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid wallet address format'
      });
    }

    // Validate role
    const validRoles = ['admin', 'issuer', 'manager', 'user'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role specified'
      });
    }

    // Check if user already exists with this email
    const existingUserByEmail = await User.findByEmail(email);
    if (existingUserByEmail) {
      return res.status(409).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Check if wallet exists with other roles (allowed)
    const existingUserByWallet = await User.findByWallet(walletAddress);
    
    if (existingUserByWallet) {
      // Wallet exists with other roles, add new role to existing user
      await existingUserByWallet.addRole(role);
      
      // Generate token with updated roles
      const token = generateToken(existingUserByWallet._id, existingUserByWallet.roles, existingUserByWallet.primaryRole);
      
      // Update last login
      await existingUserByWallet.updateLastLogin();
      
      const userResponse = existingUserByWallet.toJSON();
      
      return res.status(200).json({
        success: true,
        message: `Role ${role} added to existing wallet successfully`,
        data: {
          user: userResponse,
          token,
          availableRoles: existingUserByWallet.roles,
          currentRole: role
        }
      });
    }

    // Create new user
    const newUser = new User({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.toLowerCase().trim(),
      password,
      walletAddress: walletAddress.toLowerCase().trim(),
      roles: [role],
      primaryRole: role
    });

    await newUser.save();

    // Generate token with roles
    const token = generateToken(newUser._id, newUser.roles, newUser.primaryRole);

    // Update last login
    await newUser.updateLastLogin();

    // Remove password from response
    const userResponse = newUser.toJSON();

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: userResponse,
        token,
        availableRoles: newUser.roles,
        currentRole: role
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    // Handle mongoose validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }

    // Handle duplicate key error
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(409).json({
        success: false,
        message: `Email already exists`
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const { email, password, walletAddress, preferredRole } = req.body;

    // Validation - either email+password OR wallet address
    if ((!email || !password) && !walletAddress) {
      return res.status(400).json({
        success: false,
        message: 'Either email and password OR wallet address is required'
      });
    }

    let user;

    if (walletAddress) {
      // Login with wallet address
      const walletRegex = /^0x[a-fA-F0-9]{40}$/;
      if (!walletRegex.test(walletAddress)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid wallet address format'
        });
      }

      user = await User.findByWallet(walletAddress);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Wallet address not registered'
        });
      }
    } else {
      // Login with email and password
      user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      // Check password
      const isPasswordValid = await user.comparePassword(password);
      
      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }
    }

    // Determine current role
    let currentRole = preferredRole || user.primaryRole;
    
    // Validate preferred role
    if (preferredRole && !user.hasRole(preferredRole)) {
      return res.status(403).json({
        success: false,
        message: `User does not have ${preferredRole} role access`,
        availableRoles: user.roles
      });
    }

    // If no preferred role and user has multiple roles, use primary role
    if (!preferredRole && user.roles.length > 1) {
      currentRole = user.primaryRole;
    } else if (!preferredRole) {
      currentRole = user.roles[0];
    }

    // Generate token with role information
    const token = generateTokenWithRole(user._id, user.roles, user.primaryRole, currentRole);

    // Update last login
    await user.updateLastLogin();

    // Remove password from response
    const userResponse = user.toJSON();

    // Determine dashboard route based on role
    const dashboardRoutes = {
      admin: '/admin',
      issuer: '/issuer',
      manager: '/manager-dashboard',
      user: '/dashboard'
    };

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        token,
        currentRole,
        availableRoles: user.roles,
        dashboardRoute: dashboardRoutes[currentRole],
        hasMultipleRoles: user.roles.length > 1
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
};

// Get user profile
const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: user.toJSON()
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Update user profile
const updateProfile = async (req, res) => {
  try {
    const allowedUpdates = ['firstName', 'lastName', 'phone', 'address', 'preferences'];
    const updates = Object.keys(req.body);
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return res.status(400).json({
        success: false,
        message: 'Invalid updates'
      });
    }

    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    updates.forEach(update => {
      if (req.body[update] !== undefined) {
        user[update] = req.body[update];
      }
    });

    await user.save();

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: user.toJSON()
      }
    });

  } catch (error) {
    console.error('Update profile error:', error);
    
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Logout (client-side token removal, server-side could implement token blacklisting)
const logout = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Create user by admin (for issuer/manager accounts)
const createUserByAdmin = async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, walletAddress, role } = req.body;

    // Check if the requesting user is admin
    if (!req.user || !req.user.roles.includes('admin')) {
      return res.status(403).json({
        success: false,
        message: 'Only administrators can create issuer/manager accounts'
      });
    }

    // Validation
    if (!firstName || !lastName || !email || !password || !walletAddress || !role) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Validate wallet address format
    const walletRegex = /^0x[a-fA-F0-9]{40}$/;
    if (!walletRegex.test(walletAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid wallet address format'
      });
    }

    // Only allow issuer/manager roles for admin creation
    if (!['issuer', 'manager'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Admin can only create issuer or manager accounts'
      });
    }

    // Check if email already exists
    const existingUserByEmail = await User.findOne({ email });
    if (existingUserByEmail) {
      return res.status(409).json({
        success: false,
        message: 'Email already exists'
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      walletAddress,
      roles: [role],
      primaryRole: role,
      isVerified: true, // Admin-created users are automatically verified
      kycStatus: 'pending'
    });

    await newUser.save();

    // Generate token for the new user with roles
    const token = generateTokenWithRole(newUser._id, newUser.roles, newUser.primaryRole, role);

    // Determine dashboard route
    let dashboardRoute = '/dashboard';
    switch (role) {
      case 'issuer':
        dashboardRoute = '/issuer';
        break;
      case 'manager':
        dashboardRoute = '/manager';
        break;
    }

    res.status(201).json({
      success: true,
      message: `${role.charAt(0).toUpperCase() + role.slice(1)} account created successfully`,
      data: {
        user: {
          _id: newUser._id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email,
          roles: newUser.roles,
          primaryRole: newUser.primaryRole,
          walletAddress: newUser.walletAddress,
          isVerified: newUser.isVerified,
          kycStatus: newUser.kycStatus,
          fullName: newUser.fullName,
          createdAt: newUser.createdAt
        },
        token,
        dashboardRoute
      }
    });

  } catch (error) {
    console.error('Create user by admin error:', error);

    // Handle validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }

    // Handle duplicate key error
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(409).json({
        success: false,
        message: `Email already exists`
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error during user creation'
    });
  }
};

// Switch user role
const switchRole = async (req, res) => {
  try {
    const { newRole } = req.body;

    if (!newRole) {
      return res.status(400).json({
        success: false,
        message: 'New role is required'
      });
    }

    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if user has the requested role
    if (!user.hasRole(newRole)) {
      return res.status(403).json({
        success: false,
        message: `You do not have ${newRole} role access`,
        availableRoles: user.roles
      });
    }

    // Generate new token with the new current role
    const token = generateTokenWithRole(user._id, user.roles, user.primaryRole, newRole);

    // Determine dashboard route based on role
    const dashboardRoutes = {
      admin: '/admin',
      issuer: '/issuer',
      manager: '/manager-dashboard',
      user: '/dashboard'
    };

    res.status(200).json({
      success: true,
      message: `Successfully switched to ${newRole} role`,
      data: {
        user: user.toJSON(),
        token,
        currentRole: newRole,
        availableRoles: user.roles,
        dashboardRoute: dashboardRoutes[newRole]
      }
    });

  } catch (error) {
    console.error('Switch role error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during role switch'
    });
  }
};

// Get user roles
const getUserRoles = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        availableRoles: user.roles,
        currentRole: req.currentRole,
        primaryRole: user.primaryRole,
        hasMultipleRoles: user.roles.length > 1
      }
    });

  } catch (error) {
    console.error('Get user roles error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Verify wallet address
const verifyWallet = async (req, res) => {
  try {
    const { walletAddress } = req.body;

    if (!walletAddress) {
      return res.status(400).json({
        success: false,
        message: 'Wallet address is required'
      });
    }

    // Validate wallet address format
    const walletRegex = /^0x[a-fA-F0-9]{40}$/;
    if (!walletRegex.test(walletAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid wallet address format'
      });
    }

    const user = await User.findByWallet(walletAddress);
    
    if (user) {
      res.status(200).json({
        success: true,
        data: {
          walletExists: true,
          availableRoles: user.roles,
          userInfo: {
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email
          }
        }
      });
    } else {
      res.status(200).json({
        success: true,
        data: {
          walletExists: false,
          availableRoles: []
        }
      });
    }

  } catch (error) {
    console.error('Verify wallet error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during wallet verification'
    });
  }
};

module.exports = {
  register,
  login,
  getProfile,
  updateProfile,
  logout,
  createUserByAdmin,
  switchRole,
  getUserRoles,
  verifyWallet
};
