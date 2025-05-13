const validatePassword = (password) => {
  const minLength = /.{8,}/;
  const upper = /[A-Z]/;
  const lower = /[a-z]/;
  const number = /[0-9]/;
  const special = /[!@#$%^&*(),.?":{}|<>]/;

  return {
    length: minLength.test(password),
    uppercase: upper.test(password),
    lowercase: lower.test(password),
    number: number.test(password),
    symbol: special.test(password),
  };

 
};

export default validatePassword;
