from ecpy.curves import Curve,Point
ec = Curve.get_curve('secp256k1')

def point(x,y):
	return Point(x,y,ec)

gen = ec.generator