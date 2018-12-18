import numpy as np
import random
from collections import deque
from itertools import islice, izip, tee, count


class PerturbationOptimizer:

    def __init__(self,
        problem_size = 2,
        max_iter = 40,
        bounds = [[300.0, 1200.0], [1000.0, 2000.0], [5000.0, 12000.0]],
        init_factor_bytes = 0.1,
        init_factor_duration = 0.1,
        init_factor_offline = 0.9,
        s_factor = 1.2,
        l_factor = 3.0,
        iter_mult = 10,
        max_no_impr = 10):

        self.problem_size = problem_size
        self.bounds = bounds
        self.max_iter = max_iter
        self.init_factor_bytes = init_factor_bytes
        self.init_factor_duration = init_factor_duration
        self.init_factor_offline = init_factor_offline
        self.s_factor = s_factor
        self.l_factor = l_factor
        self.iter_mult = iter_mult
        self.max_no_impr = max_no_impr



    def run_spsa(self, vector=[204, 7.9, 50.1]):
        run_spsa(vector)

    def random_vector_with_thresholds(self, thresholds):
        return [
        (random.uniform(thresholds[0][0], thresholds[0][1])),
        (random.uniform(thresholds[1][0], thresholds[1][1])),
        (random.uniform(thresholds[2][0], thresholds[2][1]))
        ]

    def add_solutions_to_deque(self, amount):
        for i in range(amount):
            self.best_params.append(self.adaptive_random_search(
                self.max_iter,
                self.bounds,
                self.init_factor_bytes,
                self.init_factor_duration,
                self.init_factor_offline,
                self.s_factor,
                self.l_factor,
                self.iter_mult,
                self.max_no_impr
            ))

    def objective_function(self, vector, pert_vector=None):
        return (vector[2] + vector[1])/float(vector[0])

    def random_vector(self, minmax):
        """
        Returns a random 2D vector that represents a step in a random direction, based on thresholds.
        """
        return [self.rand_in_bounds(minmax[i][0], minmax[i][1]) for i in range(len(minmax))]


    def rand_in_bounds(self, min, max):
        return min + ((max-min) * random.uniform(0, 1))

    def large_step_size(self, iter, step_size, s_factor, l_factor, iter_mult):
        if iter > 0 and iter % iter_mult == 0:
            return [x * l_factor for x in step_size]
        return [x * s_factor for x in step_size]

    def take_steps(self, bounds, current, step_size, big_stepsize):
        step, big_step = {}, {}
        step["vector"] = self.take_step(bounds, current["vector"], step_size)
        step["cost"] = self.objective_function(step["vector"])
        big_step["vector"] = self.take_step(bounds, current["vector"], big_stepsize)
        big_step["cost"] = self.objective_function(big_step["vector"])

        return step, big_step

    def take_step(self, minmax, current, step_size):
        position = current
        for i in range(len(position)):
            min_i = max(minmax[i][0], current[i]-step_size[i])
            max_i = min(minmax[i][1], current[i]+step_size[i])
            position[i] = self.rand_in_bounds(min_i, max_i)
        return position

    def adaptive_random_search(self,
        max_iter=100,
        bounds=[[300, 400], [1.0, 2.0], [5.0, 12.0]],
        init_factor_bytes=0.1,
        init_factor_duration=0.1,
        init_factor_offline=0.9,
        s_factor=1.2,
        l_factor=3.0,
        iter_mult=10,
        max_no_impr=10):
        """
        Description:
            Init function for the Adaptive Random Search algorithm

        Args:
            max_iter: the maximum amount of iterations one session will conduct.
            bounds: 2D list representing the bounds for each parameter on the form [[min_a, max_a], [min_b, max_b], [min_c, max_c]]
            init_factor_bytes: initialization factor for maximum amount of bytes.
            init_factor_duration: initialization factor for maximum duration of flow (ms)
            init_factor_offline: initialization factor for maximum offline duration (ms)
            s_factor: factor for the small step size
            l_factor: factor for the large step size
            iter_mult: how often step_size should be multiplied by l_factor. iteration % iter_mult == 0
            max_no_impr: how many attempts should be tried unsuccessully before reducing the step_size by s_factor fractions.
        """
        step_size = list()
        step_size.append((bounds[0][1]-bounds[0][0]) * init_factor_bytes)
        step_size.append((bounds[1][1] - bounds[1][0]) * init_factor_duration)
        step_size.append((bounds[2][1] - bounds[2][0]) * init_factor_offline)
        current, count = {}, 0
        current["vector"] = self.random_vector(bounds)
        current["cost"] = self.objective_function(current["vector"], step_size)

        #print current["cost"]
        #print current["vector"], current

        for iter in range(max_iter):
            big_stepsize = self.large_step_size(iter, step_size, s_factor, l_factor, iter_mult)
            step, big_step = self.take_steps(bounds, current, step_size, big_stepsize)
            #print step, big_step
            # step, big_step are dictionaries that contain the estimated cost for that step
            if step["cost"] <= current["cost"] or big_step["cost"] <= current["cost"]:
                if big_step["cost"] <= step["cost"]:
                    step_size, current = big_stepsize, big_step
                else:
                    current = step
                count = 0
            else:
                count += 1
                count = 0
                if count >= max_no_impr:
                    step_size = [x / s_factor for x in step_size]
            #print(" > iteration %d \t best=%f" % (iter+1, current["cost"]))
        return current


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
        return [random.choice((-self.r, self.r)) for _ in range(self.p)]

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
    '''Helper function to estimate gradient approximation from SPSA'''
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
    return (((a/ beta*(k+1))** alpha) for k in count())

def standard_ck(c, gamma, beta):
	'''Create a generator for values of c_k in the standard form.'''
	return (((c / beta*(k+1)*0.5) ** gamma) for k in count())


def run_spsa(init_theta, beta_vector=[0.1, 0.9], n=1000, replications=40):
    dim = 3
    theta0 = init_theta
    c = standard_ck(c=1, gamma=0.101, beta=beta_vector[0])
    a = standard_ak(a=1, A=100, alpha=0.602, beta=beta_vector[1])
    delta = Bernoulli(p=dim)

    # tee splits an iterator into n independent runs of that iterator
    # iterators let us create a "lazy" list that we can just pop values from.
    # this is a quite efficient way to do it
    ac = izip(tee(a,n),tee(c,n))

    losses = []
    for a, c in islice(ac, replications):
        theta_iter = SPSA(a=a, c=c, y=y, t0=theta0, delta=delta)
        terminal_theta = nth(theta_iter, n) # Get 1000th theta
        terminal_loss = y(terminal_theta)
        losses += [terminal_loss]
    return terminal_theta # You can calculate means/variances from this data.
