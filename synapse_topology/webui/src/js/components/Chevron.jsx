import React from 'react';
import { FaChevronRight, FaChevronDown } from 'react-icons/fa'

export default ({ open }) =>
    <span className="chevron">
        {open ? <FaChevronDown /> : <FaChevronRight />}
    </span>