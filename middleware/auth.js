const jwt = require("jsonwebtoken");

module.exports = function(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({error:"no token"});
  try{
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data;
    next();
  }catch(e){
    res.status(401).json({error:"bad token"});
  }
}
