#ifndef LIBCRYPTO42_RANDOM_HH
#define LIBCRYPTO42_RANDOM_HH

#include "test.hh"
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <locale>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace rng {
	extern std::random_device device;
	extern std::mt19937_64    engine;

	std::vector<uint8_t>      get_random_data(size_t length);

	template<typename return_type, class Enable = void>
	class CauchyDistribution;

	template<typename return_type>
	class CauchyDistribution<return_type, typename std::enable_if<std::is_floating_point<return_type>::value>::type> {
	public:
		struct Params {
			return_type x0{ 0 };
			return_type gamma{ 1 };
			return_type gamma_inc{ 0.1 };
			return_type percentage_item{ .001 };

			Params(return_type _x0, return_type _gamma, return_type _gamma_inc, return_type _percentage_item)
				: x0(_x0), gamma(_gamma), gamma_inc(_gamma_inc), percentage_item(_percentage_item) {}
		};

		explicit CauchyDistribution(return_type x0, return_type gamma, return_type gamma_inc,
		                            return_type percentage_item)
			: _x0(x0), _base_gamma(gamma), _base_gamma_inc(gamma_inc), _current_gamma_inc(gamma_inc),
			  _percentage_item(percentage_item) {}

		explicit CauchyDistribution()
			: _x0(), _base_gamma(1), _base_gamma_inc(0.1), _current_gamma_inc(0.1), _percentage_item(0.001) {}

		explicit CauchyDistribution(const Params &params)
			: _x0(params.x0), _base_gamma(params.gamma), _base_gamma_inc(params.gamma_inc),
			  _current_gamma_inc(params.gamma_inc), _percentage_item(params.percentage_item) {}

		void debug() {
			_dbg = !_dbg;
		}

		template<typename T, typename = std::is_arithmetic<T> >
		return_type operator()(T item) {
			_x0                    = static_cast<return_type>(item);
			bool        ret_is_set = false;
			return_type ret;

			if (_current_gamma_inc == _base_gamma_inc) {
				if (item == 0) {
					ret        = 0;
					ret_is_set = true;
					reset_params();
				}
				if (item == 1 || (item & (item - 1)) == 0) {
					ret                = _x0;
					_current_gamma_inc = _base_gamma_inc;
					apply_gamma_inc();
					ret_is_set = true;
					compute_next_gamma(true);
				}
			}

			if (static_cast<size_t>(cauchy.a()) != item) {
				reset_params();
			} else {
				apply_gamma_inc();
				compute_next_gamma(false);
			}

			if (!ret_is_set) {
				do {
					ret = utils::ceil(cauchy(engine));
				} while (ret <= 1);
			}

			if (_dbg)
				history.emplace_back(cauchy.a(), cauchy.b(), _current_gamma_inc, _percentage_item, item, ret);
			return ret;
		}

		void dump_history(std::ostream &os) {
			static std::array<Column, 6> columns{
				Column("Items", "Items", 12, false, false, true),
				Column("Returned", "Returned", 13, false, false, true),
				Column("Params", "Params", 23, false, true, true),
				Column("𝛾", "Params.𝛾", 10, true, false, true),
				Column("x₀", "Params.x₀", 12, true, false, true),
				Column("gamma_inc", "gamma_inc", 15, false, false, true),
			};
			const static std::string column_separator = "|";
			const static std::string line_separator   = "-";
			const static std::string corner_separator = "+";

			if (columns[2].sub_lst.empty()) {
				columns[2].sub_lst.emplace_back(columns[3]);
				columns[2].sub_lst.emplace_back(columns[4]);
			}

			if (!_dbg)
				return;

			auto print_line = [&os](const std::string &line_fill, const std::string &column_fill, bool need_sub_sep) {
				os << column_fill;

				for (const auto &col: columns) {
					if ((need_sub_sep && col.has_sub) || (!need_sub_sep && col.sub))
						continue;

					size_t nb = col.size;

					for (size_t j = 0; j < nb; j++)
						os << line_fill;
					os << column_fill;
				}

				os << std::endl;
			};
			auto print_line_content = [&os](const std::vector<std::string> &content) {
				os << column_separator;
				size_t i = 0;

				for (const auto &col: columns) {
					const auto &str = content[i];

					if (col.has_sub)
						continue;

					os << " " << std::setw(col.size - 1) << (col.align_left ? std::left : std::right);
					os << str << column_separator;

					i++;
				}
				os << std::endl;
			};

			print_line(line_separator, corner_separator, false);

			os << column_separator;
			for (const auto &col: columns) {
				if (col.sub)
					continue;

				if (!col.has_sub)
					os << std::setw(col.size) << "";
				else
					os << " " << std::setw(col.size - 1) << (col.align_left ? std::left : std::right) << col.name;

				os << column_separator;
			}
			os << std::endl << column_separator;

			for (const auto &col: columns) {
				if (col.sub)
					continue;

				if (col.has_sub) {
					std::ostringstream oss;
					for (size_t i = 0; i < col.sub_lst.size(); i++) {
						const auto &sub = col.sub_lst[i];
						oss << std::string(sub.size, line_separator[0]);

						if (i + 1 < col.sub_lst.size())
							oss << corner_separator;
					}
					os << oss.str();
				} else
					os << " " << std::setw(col.size - 1) << (col.align_left ? std::left : std::right) << col.name;

				os << column_separator;
			}

			os << std::endl;
			os << column_separator;
			for (size_t i = 0; i < columns.size(); i++) {
				const auto &col = columns[i];
				if (col.has_sub)
					continue;

				if (!col.sub)
					os << std::setw(col.size) << "";
				else {

#ifdef HAVE_CLANG_COMPILER
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
					std::wstring_convert<std::codecvt_utf8_utf16<wchar_t> > converter;
#ifdef HAVE_CLANG_COMPILER
#pragma clang diagnostic pop
#endif

					std::wstring w            = converter.from_bytes(col.name.data());
					bool         has_sub_prev = (i >= 1 && columns[i - 1].sub);
					os << " " << std::setw(col.size + (col.name.length() - w.length()) - 1)
					   << (col.align_left ? std::left : std::right) << col.name << (!has_sub_prev ? " " : "");
				}

				os << column_separator;
			}
			os << std::endl;

			print_line(line_separator, corner_separator, true);

			std::vector<std::string> content;
			content.resize(columns.size());
			for (const auto &param: history) {
				content[0] = std::to_string(param.item);
				content[1] = utils::to_string_with_precision(param.returned, 3);
				content[2] = utils::to_string_with_precision(param.gamma, 3);
				content[3] = utils::to_string_with_precision(param.x0, 3);
				content[4] = utils::to_string_with_precision(param.gamma_inc, 3);

				print_line_content(content);
			}

			print_line(line_separator, corner_separator, true);
		}

	private:
		struct ParamHistory : public Params {
			size_t      item;
			return_type returned;

			ParamHistory(return_type _x0, return_type _gamma, return_type _gamma_inc, return_type _percentage_item,
			             size_t _item, return_type _returned)
				: Params(_x0, _gamma, _gamma_inc, _percentage_item), item(_item), returned(_returned) {}
		};

		struct Column {
			std::string         name;
			std::string         path;
			size_t              size;
			bool                sub;
			bool                has_sub;
			bool                align_left;

			std::vector<Column> sub_lst;

			Column(std::string _name, std::string _path, size_t _size, bool _sub, bool _has_sub, bool _align_left)
				: name(std::move(_name)), path(std::move(_path)), size(_size), sub(_sub), has_sub(_has_sub),
				  align_left(_align_left) {}
		};

		void compute_next_gamma(bool reset) {
			if (reset)
				_current_gamma_inc = _base_gamma_inc * _x0 * _percentage_item;
			else
				_current_gamma_inc += _base_gamma_inc * _x0 * _percentage_item;
		}

		void reset_params() {
			_current_gamma_inc = _base_gamma_inc;
			cauchy.param(typename decltype(cauchy)::param_type(_x0, _base_gamma));
		}

		void apply_gamma_inc() {
			cauchy.param(typename decltype(cauchy)::param_type(_x0, cauchy.b() + _current_gamma_inc));
		}

		return_type                           _x0;
		return_type                           _base_gamma;
		return_type                           _base_gamma_inc;
		return_type                           _current_gamma_inc;
		return_type                           _percentage_item;

		std::cauchy_distribution<return_type> cauchy;
		bool                                  _dbg{ false };
		std::vector<ParamHistory>             history;
	};
}


#endif// LIBCRYPTO42_RANDOM_HH
