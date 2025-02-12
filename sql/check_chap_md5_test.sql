CREATE EXTENSION check_chapmd5_password;

SELECT check_chapmd5_password('00777f2a3f6a2e661947b520c6777e0b25', '45c915d82d67257209048420a31292d3', 'password');
