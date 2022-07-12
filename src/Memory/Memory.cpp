#include "Memory/Memory.hpp"

#include <sys/mman.h>
#include <iostream>

/// Allocates a MEM_SIZE bytes of memory by using super or huge pages.
void Memory::allocate_memory(size_t mem_size) {
  this->size = mem_size;
  volatile char *target = nullptr;
  FILE *fp;

  if (superpage) {
    // allocate memory using super pages
    fp = fopen(hugetlbfs_mountpoint.c_str(), "w+");
    if (fp==nullptr) {
      Logger::log_info(format_string("Could not mount superpage from %s. Error:", hugetlbfs_mountpoint.c_str()));
      Logger::log_data(std::strerror(errno));
      exit(EXIT_FAILURE);
    }
    auto mapped_target = mmap((void *) start_address, MEM_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | (30UL << MAP_HUGE_SHIFT), fileno(fp), 0);
    if (mapped_target==MAP_FAILED) {
      perror("mmap");
      exit(EXIT_FAILURE);
    }
    target = (volatile char*) mapped_target;
  } else {
    // allocate memory using huge pages
    assert(posix_memalign((void **) &target, MEM_SIZE, MEM_SIZE)==0);
    assert(madvise((void *) target, MEM_SIZE, MADV_HUGEPAGE)==0);
    memset((char *) target, 'A', MEM_SIZE);
    // for khugepaged
    Logger::log_info("Waiting for khugepaged.");
    sleep(10);
  }

  if (target!=start_address) {
    Logger::log_error(format_string("Could not create mmap area at address %p, instead using %p.",
        start_address, target));
    start_address = target;
  }

  // initialize memory with random but reproducible sequence of numbers
  initialize(DATA_PATTERN::STRIPE_0F);
}

void Memory::initialize(DATA_PATTERN data_pattern) {
  Logger::log_info("Initializing memory with pseudorandom sequence.");

// enum class DATA_WRITE_PATTERN : char {
//   STRIPE_0F, STRIPE_F0, CHECK_5A, CHECK_A5, CHECK_69, CHECK_96
//};
        int fill_value_even = 0x00000000;
        int fill_value_odd = 0xffffffff;
      if (data_pattern == DATA_PATTERN::STRIPE_0F) {
        fill_value_even = 0x00000000;
        fill_value_odd = 0xffffffff;
      } else if (data_pattern ==  DATA_PATTERN::STRIPE_F0) {
        fill_value_even = 0xffffffff;
        fill_value_odd = 0x00000000;
      } else if (data_pattern ==  DATA_PATTERN::CHECK_5A) {
        fill_value_even = 0x55555555;
        fill_value_odd = 0xaaaaaaaa;
      } else if (data_pattern ==  DATA_PATTERN::CHECK_A5) {
        fill_value_even = 0xaaaaaaaa;
        fill_value_odd = 0x55555555;
      } else if (data_pattern ==  DATA_PATTERN::CHECK_69) {
        fill_value_even = 0x66666666;
        fill_value_odd = 0x99999999;
      } else if (data_pattern ==  DATA_PATTERN::CHECK_96) {
        fill_value_even = 0x9999999;
        fill_value_odd = 0x66666666;
      } else {
        Logger::log_error("Could not initialize memory with given (unknown) DATA_PATTERN.");
      }
  //size_t ROW_SHIFT = 0b000000000000001000000000000000;
  auto ROW_SHIFT = 15;
  for (uint64_t cur_page = 0; cur_page < Memory::size; cur_page += getpagesize()) {
    // reseed rand to have a sequence of reproducible numbers, using this we can compare the initialized values with
    // those after hammering to see whether bit flips occurred
    for (uint64_t cur_pageoffset = 0; cur_pageoffset < (uint64_t) getpagesize(); cur_pageoffset += sizeof(int)) {

      uint64_t offset = cur_page + cur_pageoffset;
      auto p = (size_t) Memory::start_address + offset;
      auto row = (p >> ROW_SHIFT) % 2;
      //std::cout << "init address by int " << (void *) (start_address+offset) << " " << std::endl;
      // std::cout << "Row even or odd " << row << " " << std::endl;
      if (row==0){
        *((int *) (Memory::start_address + offset)) = fill_value_even;
      } else {
        *((int *) (Memory::start_address + offset)) = fill_value_odd;
      }
    }
  }
}

size_t Memory::check_memory(PatternAddressMapper &mapping, bool reproducibility_mode, bool verbose) {
  flipped_bits.clear();

  auto victim_rows = mapping.get_victim_rows();
  if (verbose) Logger::log_info(format_string("Checking %zu victims for bit flips.", victim_rows.size()));

  size_t sum_found_bitflips = 0;
  for (const auto &victim_row : victim_rows) {
    sum_found_bitflips += check_memory_internal(mapping, victim_row,
        (volatile char *) ((uint64_t)victim_row+DRAMAddr::get_row_increment()), reproducibility_mode, verbose);
  }
  return sum_found_bitflips;
}


size_t Memory::check_victim_memory(std::vector<volatile char *> &victim, size_t row_inc, size_t distance, size_t bank, size_t even) {
  flipped_bits.clear();
  // create a "fake" pattern mapping to keep this method for backward compatibility
  PatternAddressMapper pattern_mapping;
  size_t sum_found_bitflips = 0;
  Logger::log_info(format_string("Checking %zu victims for bit flips.", victim.size()));

  for (size_t i = 0; i <victim.size(); i++) {
    sum_found_bitflips += check_memory_internal(pattern_mapping, victim[i],
        true, true, row_inc, distance, bank, victim.size()-1, even);
    
//    Logger::log_info(format_string("Checking : %zu, 0x%llx ", i, aggressors[i]));
  }
  Logger::log_info(format_string("Flip bits : %zu, # of victim : %zu", sum_found_bitflips, victim.size()));
  return sum_found_bitflips;
}

size_t Memory::check_memory(std::vector<volatile char *> &aggressors, size_t row_inc, size_t distance, size_t bank) {
  flipped_bits.clear();
  // create a "fake" pattern mapping to keep this method for backward compatibility
  PatternAddressMapper pattern_mapping;
  size_t sum_found_bitflips = 0;
  Logger::log_info(format_string("Checking %zu victims for bit flips.", aggressors.size()));

  for (size_t i = 0; i <aggressors.size(); i++) {
    sum_found_bitflips += check_memory_internal(pattern_mapping, aggressors[i],
        (volatile char *) ((uint64_t)aggressors[i]+DRAMAddr::get_row_increment()), true, true, row_inc, distance, bank, aggressors.size());
    sum_found_bitflips += check_memory_internal(pattern_mapping, 
        (volatile char *) ((uint64_t)aggressors[i]-DRAMAddr::get_row_increment()), aggressors[i],true, true, row_inc, distance, bank, aggressors.size());
//    Logger::log_info(format_string("Checking : %zu, 0x%llx ", i, aggressors[i]));
  }
  Logger::log_info(format_string("Flip bits : %zu, # of Aggressors : %zu", sum_found_bitflips, aggressors.size()));
  return sum_found_bitflips;
}


size_t Memory::check_memory(const volatile char *start, const volatile char *end) {
  flipped_bits.clear();
  // create a "fake" pattern mapping to keep this method for backward compatibility
  PatternAddressMapper pattern_mapping;
  return check_memory_internal(pattern_mapping, start, end, false, true);
}

size_t Memory::check_memory_internal(PatternAddressMapper &mapping,
                                     const volatile char *start,
                                     const volatile char *end,
                                     bool reproducibility_mode,
                                     bool verbose) {
  // counter for the number of found bit flips in the memory region [start, end]
  size_t found_bitflips = 0;

  if (start==nullptr || end==nullptr || ((uint64_t) start > (uint64_t) end)) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(format_string("Start addr.: %s", DRAMAddr((void *) start).to_string().c_str()));
    Logger::log_data(format_string("End addr.: %s", DRAMAddr((void *) end).to_string().c_str()));
    return found_bitflips;
  }

  auto check_offset = 1;

  auto row_increment = DRAMAddr::get_row_increment();

//  Logger::log_info(format_string("row increment 0x%llx.", row_increment));

  start -= row_increment*check_offset;
  end += row_increment*check_offset;

//    Logger::log_data(format_string("Start addr.: %s", DRAMAddr((void *) start).to_string().c_str()));
//    Logger::log_data(format_string("End addr.: %s", DRAMAddr((void *) end).to_string().c_str()));

  auto start_offset = (uint64_t) (start - start_address);

  const auto pagesize = static_cast<size_t>(getpagesize());
  start_offset = (start_offset/pagesize)*pagesize;

  auto end_offset = start_offset + (uint64_t) (end - start);
  end_offset = (end_offset/pagesize)*pagesize;

  void *page_raw = malloc(pagesize);
  if (page_raw == nullptr) {
    Logger::log_error("Could not create temporary page for memory comparison.");
    exit(EXIT_FAILURE);
  }
  memset(page_raw, 0, pagesize);
  int *page = (int*)page_raw;

  // for each page (4K) in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += pagesize) {
    // reseed rand to have the desired sequence of reproducible numbers
    srand(static_cast<unsigned int>(i*pagesize));

    // fill comparison page with expected values generated by rand()
    for (size_t j = 0; j < (unsigned long) pagesize/sizeof(int); ++j)
      page[j] = rand();

    uint64_t addr = ((uint64_t)start_address+i);
  //  Logger::log_data(format_string("checking addr.: %s", DRAMAddr((void *) addr).to_string().c_str()));
    // check if any bit flipped in the page using the fast memcmp function, if any flip occurred we need to iterate over
    // each byte one-by-one (much slower), otherwise we just continue with the next page
    if ((addr+ pagesize) < ((uint64_t)start_address+size) && memcmp((void*)addr, (void*)page, pagesize) == 0)
      continue;

    // iterate over blocks of 4 bytes (=sizeof(int))
    for (uint64_t j = 0; j < (uint64_t) pagesize; j += sizeof(int)) {
      uint64_t offset = i + j;
      volatile char *cur_addr = start_address + offset;

      // if this address is outside the superpage we must not proceed to avoid segfault
      if ((uint64_t)cur_addr >= ((uint64_t)start_address+size))
        continue;

      // clear the cache to make sure we do not access a cached value
      clflushopt(cur_addr);
      mfence();

      // if the bit did not flip -> continue checking next block
      int expected_rand_value = page[j/sizeof(int)];
      if (*((int *) cur_addr)==expected_rand_value)
        continue;

      // if the bit flipped -> compare byte per byte
      for (unsigned long c = 0; c < sizeof(int); c++) {
        volatile char *flipped_address = cur_addr + c;
        if (*flipped_address != ((char *) &expected_rand_value)[c]) {
          const auto flipped_addr_dram = DRAMAddr((void *) flipped_address);
          assert(flipped_address == (volatile char*)flipped_addr_dram.to_virt());
          const auto flipped_addr_value = *(unsigned char *) flipped_address;
          const auto expected_value = ((unsigned char *) &expected_rand_value)[c];
          if (verbose) {
            Logger::log_bitflip(flipped_address, flipped_addr_dram.row,
                expected_value, flipped_addr_value, (size_t) time(nullptr), true);
          }
          // store detailed information about the bit flip
          BitFlip bitflip(flipped_addr_dram, (expected_value ^ flipped_addr_value), flipped_addr_value);
          // ..in the mapping that triggered this bit flip
          if (!reproducibility_mode) {
            if (mapping.bit_flips.empty()) {
              Logger::log_error("Cannot store bit flips found in given address mapping.\n"
                                "You need to create an empty vector in PatternAddressMapper::bit_flips before calling "
                                "check_memory.");
            }
            mapping.bit_flips.back().push_back(bitflip);
          }
          // ..in an attribute of this class so that it can be retrived by the caller
          flipped_bits.push_back(bitflip);
          found_bitflips += bitflip.count_bit_corruptions();
        }
      }

      // restore original (unflipped) value
      *((int *) cur_addr) = expected_rand_value;

      // flush this address so that value is committed before hammering again there
      clflushopt(cur_addr);
      mfence();
    }
  }
  
  free(page);
  return found_bitflips;
}

size_t Memory::check_memory_internal(PatternAddressMapper &mapping,
                                     const volatile char *start,
                                     const volatile char *end,
                                     bool reproducibility_mode,
                                     bool verbose, size_t row_inc, size_t distance, size_t bank, size_t agg_size) {
  // counter for the number of found bit flips in the memory region [start, end]
  size_t found_bitflips = 0;

  if (start==nullptr || end==nullptr || ((uint64_t) start > (uint64_t) end)) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(format_string("Start addr.: %s", DRAMAddr((void *) start).to_string().c_str()));
    Logger::log_data(format_string("End addr.: %s", DRAMAddr((void *) end).to_string().c_str()));
    return found_bitflips;
  }

  auto check_offset = 1;

  auto row_increment = DRAMAddr::get_row_increment();

//  Logger::log_info(format_string("row increment 0x%llx.", row_increment));

  start -= row_increment*check_offset;
  end += row_increment*check_offset;

//    Logger::log_data(format_string("Start addr.: %s", DRAMAddr((void *) start).to_string().c_str()));
//    Logger::log_data(format_string("End addr.: %s", DRAMAddr((void *) end).to_string().c_str()));

  auto start_offset = (uint64_t) (start - start_address);

  const auto pagesize = static_cast<size_t>(getpagesize());
  start_offset = (start_offset/pagesize)*pagesize;

  auto end_offset = start_offset + (uint64_t) (end - start);
  end_offset = (end_offset/pagesize)*pagesize;

  void *page_raw = malloc(pagesize);
  if (page_raw == nullptr) {
    Logger::log_error("Could not create temporary page for memory comparison.");
    exit(EXIT_FAILURE);
  }
  memset(page_raw, 0, pagesize);
  int *page = (int*)page_raw;

  // for each page (4K) in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += pagesize) {
    // reseed rand to have the desired sequence of reproducible numbers
    srand(static_cast<unsigned int>(i*pagesize));

    // fill comparison page with expected values generated by rand()
    for (size_t j = 0; j < (unsigned long) pagesize/sizeof(int); ++j)
      page[j] = rand();

    uint64_t addr = ((uint64_t)start_address+i);
  //  Logger::log_data(format_string("checking addr.: %s", DRAMAddr((void *) addr).to_string().c_str()));
    // check if any bit flipped in the page using the fast memcmp function, if any flip occurred we need to iterate over
    // each byte one-by-one (much slower), otherwise we just continue with the next page
    if ((addr+ pagesize) < ((uint64_t)start_address+size) && memcmp((void*)addr, (void*)page, pagesize) == 0)
      continue;

    // iterate over blocks of 4 bytes (=sizeof(int))
    for (uint64_t j = 0; j < (uint64_t) pagesize; j += sizeof(int)) {
      uint64_t offset = i + j;
      volatile char *cur_addr = start_address + offset;

      // if this address is outside the superpage we must not proceed to avoid segfault
      if ((uint64_t)cur_addr >= ((uint64_t)start_address+size))
        continue;

      // clear the cache to make sure we do not access a cached value
      clflushopt(cur_addr);
      mfence();

      // if the bit did not flip -> continue checking next block
      int expected_rand_value = page[j/sizeof(int)];
      if (*((int *) cur_addr)==expected_rand_value)
        continue;

      // if the bit flipped -> compare byte per byte
      for (unsigned long c = 0; c < sizeof(int); c++) {
        volatile char *flipped_address = cur_addr + c;
        if (*flipped_address != ((char *) &expected_rand_value)[c]) {
          const auto flipped_addr_dram = DRAMAddr((void *) flipped_address);
          assert(flipped_address == (volatile char*)flipped_addr_dram.to_virt());
          const auto flipped_addr_value = *(unsigned char *) flipped_address;
          const auto expected_value = ((unsigned char *) &expected_rand_value)[c];
          if (verbose) {
            Logger::log_bitflip(flipped_address, flipped_addr_dram.row,
                expected_value, flipped_addr_value, (size_t) time(nullptr), true, row_inc, distance, bank, agg_size);
          }
          // store detailed information about the bit flip
          BitFlip bitflip(flipped_addr_dram, (expected_value ^ flipped_addr_value), flipped_addr_value);
          // ..in the mapping that triggered this bit flip
          if (!reproducibility_mode) {
            if (mapping.bit_flips.empty()) {
              Logger::log_error("Cannot store bit flips found in given address mapping.\n"
                                "You need to create an empty vector in PatternAddressMapper::bit_flips before calling "
                                "check_memory.");
            }
            mapping.bit_flips.back().push_back(bitflip);
          }
          // ..in an attribute of this class so that it can be retrived by the caller
          flipped_bits.push_back(bitflip);
          found_bitflips += bitflip.count_bit_corruptions();
        }
      }

      // restore original (unflipped) value
      *((int *) cur_addr) = expected_rand_value;

      // flush this address so that value is committed before hammering again there
      clflushopt(cur_addr);
      mfence();
    }
  }
  
  free(page);
  return found_bitflips;
}


size_t Memory::check_memory_internal(PatternAddressMapper &mapping,
                                     const volatile char *start,
                                     bool reproducibility_mode,
                                     bool verbose, size_t row_inc, size_t distance, size_t bank, size_t agg_size, size_t even) {
  // counter for the number of found bit flips in the memory region [start, end]
  size_t found_bitflips = 0;

  if (start==nullptr) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(format_string("Start addr.: %s", DRAMAddr((void *) start).to_string().c_str()));
    return found_bitflips;
  }
  auto start_offset = (uint64_t) (start - start_address);

  volatile char *cur_addr = start_address + start_offset;

  clflushopt(cur_addr);
  mfence();

  auto start_dram = DRAMAddr((void *) start);
  volatile char * start_addr = (volatile char *) start_dram.to_virt();
  
  char compare_char=0;
  int compare_int=0;

  if (even%2 == 0){
    if (start_dram.row%2 == 0){
      compare_char=0x00;
      compare_int=0x00000000;
    } else {
      compare_char=0xff;
      compare_int=0xffffffff;
    }
  } else {
    if (start_dram.row%2 == 0){
      compare_char=0xff;
      compare_int=0xffffffff;
    } else {
      compare_char=0x00;
      compare_int=0x00000000;
    }
  }

   const auto pagesize = static_cast<size_t>(getpagesize());


  void *page_raw = malloc(pagesize*2);
  if (page_raw == nullptr) {
    Logger::log_error("Could not create temporary page for memory comparison.");
    exit(EXIT_FAILURE);
  }

  memset(page_raw, compare_char, pagesize*2);
  int *page = (int*)page_raw;
  char expected_value = compare_char;

  for (int i = 0; i < 8192; i += sizeof(int)) {
 //       std::cout << "read address by int " << (void *) start_addr << " " << std::endl;
 //       std::cout << "inner loop i " << i << " " << std::endl;
    if (memcmp((void*)start_addr, (void*)page, sizeof(int)) == 0){
//    if ((start_addr+ sizeof(int)) < ((uint64_t)start_address+size) && memcmp((void*)start_addr, (void*)page, sizeof(int)) == 0){
        start_dram.add_inplace(0, 0, sizeof(int));
        start_addr = (volatile char *) start_dram.to_virt();
      continue;}

    for (unsigned long c = 0; c < sizeof(int); c++) {
          volatile char *read_address = start_addr + c;
          const char read_value = *(unsigned char *) read_address;
          
          if (read_value==expected_value){
          ;
          } else {
            // if (expected_value == (char) 0xff)
            //   std::cout << "read value " << read_value << " expected value " << expected_value <<std::endl;

            const auto flipped_addr_dram = DRAMAddr((void *) read_address);
            assert(read_address == (volatile char*)flipped_addr_dram.to_virt());

              if (verbose) {
                Logger::log_bitflip(read_address, flipped_addr_dram.row, flipped_addr_dram.col,
                     read_value, expected_value, (size_t) time(nullptr), true, row_inc, distance, bank, agg_size);
              }
              // store detailed information about the bit flip
              BitFlip bitflip(flipped_addr_dram, (expected_value ^ read_value), read_value);
              // ..in the mapping that triggered this bit flip
              if (!reproducibility_mode) {
                if (mapping.bit_flips.empty()) {
                  Logger::log_error("Cannot store bit flips found in given address mapping.\n"
                                    "You need to create an empty vector in PatternAddressMapper::bit_flips before calling "
                                    "check_memory.");
                }
                mapping.bit_flips.back().push_back(bitflip);
              }
              // ..in an attribute of this class so that it can be retrived by the caller
              flipped_bits.push_back(bitflip);
              found_bitflips += bitflip.count_bit_corruptions();
              // restore background  value
              *((int *) start_addr) = compare_int;
            }
        
    }
      start_dram.add_inplace(0, 0, sizeof(int));
      start_addr = (volatile char *) start_dram.to_virt();
    }
      // flush this address so that value is committed before hammering again there
      clflushopt(cur_addr);
      mfence();
      free(page);
      return found_bitflips;
}




Memory::Memory(bool use_superpage) : size(0), superpage(use_superpage) {
}

Memory::~Memory() {
  if (munmap((void *) start_address, size)==-1) {
    Logger::log_error("munmap failed with error:");
    Logger::log_data(std::strerror(errno));
  }
}

volatile char *Memory::get_starting_address() const {
  return start_address;
}

std::string Memory::get_flipped_rows_text_repr() {
  // first extract all rows, otherwise it will not be possible to know in advance whether we we still
  // need to add a separator (comma) to the string as upcoming DRAMAddr instances might refer to the same row
  std::set<size_t> flipped_rows;
  for (const auto &da : flipped_bits) {
    flipped_rows.insert(da.address.row);
  }

  std::stringstream ss;
  for (const auto &row : flipped_rows) {
    ss << row;
    if (row!=*flipped_rows.rbegin()) ss << ",";
  }
  return ss.str();
}


