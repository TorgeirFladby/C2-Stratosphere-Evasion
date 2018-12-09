from itertools import islice, izip, tee, count
import random
import numpy as np



class Bernoulli:
    def __init__(self, r=1, p=3):
        """
        The bernoulli distribution of +/- 1 is the distribution we choose for our delta-k vector
        This is in order to meet the requirements for the algorithm as described in https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=705889,
        in that uniform or normal random variables are not allowed. Each variable should have 1/2 probability of occurrence.
        """
        self.p = p
        self.r = r

    def __call__(self):
        return [random.choice((-self.r, self.r)) for _ in xrange(self.p)]

def nth(iterable, n, default=None):
    """Returns the nth item or a default value"""
    return next(islice(iterable, n, None), default)


def y(theta):
    """The loss function that returns seconds per Byte sent. Adding noise to time_between_network_flows."""
    return ((theta[1] + theta[2]) / theta[0]) - ((theta[2] * 0.01) + random.gauss(0, 0.1))

def identity(id):
    return id

def SPSA(y, t0, a, c, delta, constraint=identity):
    """
	Creates an Simultaneous Perturbation Stochastic Approximation iterator.
	y - a function of theta that returns a scalar
	t0 - the starting value of theta
	a - an iterable of a_k values
	c - an iterable of c_k values
	delta - a function of no parameters which creates the delta vector
	constraint - a function of theta that returns theta
	"""
    theta = t0

    # Pull off the ak and ck values forever
    for ak, ck in izip(a, c):
        # Get estimated gradient
        gk = estimate_gk(y, theta, delta, ck)

        # Adjust theta estimate using SA
        theta = [t - ak * gkk for t, gkk in izip(theta, gk)]

        # Constrain
        theta = constraint(theta)

        yield theta # This makes this function become an iterator

def estimate_gk(y, theta, delta, ck):
    '''Helper function to estimate gk from SPSA'''
    # Generate Delta vector
    delta_k = delta()
    # Get the two perturbed values of theta
    ta = [t + ck * dk for t, dk in izip(theta, delta_k)]
    #print "Perturbed t_a: "
    #print ta
    tb = [t - ck * dk for t, dk in izip(theta, delta_k)]
    #print "Perturbed t_b: "
    #print tb

	# Calculate g_k(theta_k)
    ya, yb = y(ta), y(tb)
    #print "Result of y(ta): %f \t Result of y(tb): %f" % (ya, yb)
    #print "Calculating G_k ..."
    gk = [(ya-yb) / (2*ck*dk) for dk in delta_k]

    return gk

def standard_ak(a, A, alpha, beta):
        '''Create a generator for values of a_k in the standard form.'''
        # Parentheses makes this an iterator comprehension
        # count() is an infinite iterator as 0, 1, 2, ...
	return ( (a/ beta)** alpha for k in count() )

def standard_ck(c, gamma, beta):
	'''Create a generator for values of c_k in the standard form.'''
	return ( (c / beta) ** gamma for k in count() )


def run_spsa(init_theta, beta_vector, n=1000, replications=40):
    dim = 3
    theta0 = init_theta
    c = standard_ck(c=1, gamma=0.101, beta=beta_vector[0])
    a = standard_ak(a=1, A=100, alpha=0.602, beta=beta_vector[1])
    delta = Bernoulli(p=dim)
    print delta()


    # tee is a useful function to split an iterator into n independent runs of that iterator
    ac = izip(tee(a,n),tee(c,n))

    losses = []

    for a, c in islice(ac, replications):
        theta_iter = SPSA(a=a, c=c, y=y, t0=theta0, delta=delta)
        terminal_theta = nth(theta_iter, n) # Get 1000th theta
        terminal_loss = y(terminal_theta)
        losses += [terminal_loss]


    print terminal_theta
    return terminal_theta # You can calculate means/variances from this data.
