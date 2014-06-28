/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <iterator>

namespace keepass {

template <typename C>
class bounds_checked_iterator :
    public std::iterator<std::output_iterator_tag, void, void, void, void>
{
 protected:
  typename C::iterator first_;
  typename C::iterator last_;

 public:
  explicit bounds_checked_iterator(C& container) :
      first_(container.begin()), last_(container.end()) {}

  bounds_checked_iterator& operator=(const typename C::value_type& value) {
    if (first_ == last_)
      throw std::out_of_range("assigning outside container limits.");

    *first_ = value;
    return *this;
  }

  bounds_checked_iterator& operator=(typename C::value_type&& value) {
    if (first_ == last_)
      throw std::out_of_range("assigning outside container limits.");

    *first_ = std::move(value);
    return *this;
  }

  bounds_checked_iterator& operator*() {
    return *this;
  }

  bounds_checked_iterator& operator++() {
    first_++;
    return *this;
  }

  bounds_checked_iterator operator++(int) {
    ++first_;
    return *this;
  }
};

template <typename C>
inline bounds_checked_iterator<C> bounds_checked(C& container) {
  return bounds_checked_iterator<C>(container);
}

} // namespace keepass
