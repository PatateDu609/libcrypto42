#include "random.hh"

#ifdef __APPLE__
#	include <sys/random.h>
#else
#	include <unistd.h>
#endif

using rng::CauchyDistribution;

std::random_device rng::device;
std::mt19937_64    rng::engine(rng::device());

std::vector<uint8_t> rng::get_random_data(size_t length) {
	const size_t         MAX_LENGTH = 256;
	std::vector<uint8_t> res;
	res.resize(length);

	if (res.size() <= MAX_LENGTH) {
		if (getentropy(res.data(), res.size()))
			throw std::runtime_error(strerror(errno));
		return res;
	}

	std::vector<uint8_t> buffer(MAX_LENGTH, 0);
	size_t               i = 0;
	for (; i < length; i += MAX_LENGTH) {
		if (getentropy(buffer.data(), buffer.size()))
			throw std::runtime_error(strerror(errno));

		res.insert(res.end(), buffer.begin(), buffer.end());
		buffer.assign(MAX_LENGTH, 0);
	}

	if (i < length) {
		res.assign(length - i, 0);
		if (getentropy(res.data(), res.size()))
			throw std::runtime_error(strerror(errno));
		return res;
	}

	return res;
}