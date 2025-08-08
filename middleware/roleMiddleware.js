// Role-based authorization middleware
const roleMiddleware = (allowedRoles) => {
  return (req, res, next) => {
    try {
      // Check if user is authenticated (should be set by authMiddleware)
      if (!req.user || !req.userRoles) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      // Check if user has any of the allowed roles
      const hasRequiredRole = req.userRoles.some(role => allowedRoles.includes(role));

      if (!hasRequiredRole) {
        return res.status(403).json({
          success: false,
          message: `Access denied. Required roles: ${allowedRoles.join(', ')}. Your roles: ${req.userRoles.join(', ')}`
        });
      }

      // User has required role, proceed
      next();
    } catch (error) {
      console.error('Role middleware error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error in role authorization'
      });
    }
  };
};

// Specific role middlewares
const adminOnly = roleMiddleware(['admin']);
const issuerOnly = roleMiddleware(['issuer']);
const managerOnly = roleMiddleware(['manager']);
const issuerOrAdmin = roleMiddleware(['issuer', 'admin']);
const managerOrAdmin = roleMiddleware(['manager', 'admin']);
const anyRole = roleMiddleware(['admin', 'issuer', 'manager', 'user']);

module.exports = {
  roleMiddleware,
  adminOnly,
  issuerOnly,
  managerOnly,
  issuerOrAdmin,
  managerOrAdmin,
  anyRole
};
