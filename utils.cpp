#include <cmath> //abs()
#include <string>
#include <vector>
#include <chrono>

class Time
{
private:
    uint64_t milliseconds;

public:
    Time(uint64_t milli) : milliseconds(milli) {};


    uint64_t asMilliseconds()
    {
        return this->milliseconds;
    }

    float asSeconds()
    {
        return (float)(this->milliseconds)/1000.0;
    }

    Time operator-(const Time &t1)
    {
        return Time(std::labs(this->milliseconds - t1.milliseconds));
    }
};

class Clock
{
private:
    std::chrono::high_resolution_clock::time_point start;

public:
    Clock()
    {
        this->start = std::chrono::high_resolution_clock::now();
    }

    Time getElapsedTime()
    {
        return Time(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - this->start).count());
    }

    Time restart()
    {
        auto t = this->getElapsedTime();
        this->start = std::chrono::high_resolution_clock::now();
        return t;
    }
};

class RandomNumberBetween
{
public:
    RandomNumberBetween(int low, int high)
    : random_engine_{std::random_device{}()}
    , distribution_{low, high}
    {
    }
    int operator()()
    {
        return distribution_(random_engine_);
    }
private:
    std::mt19937 random_engine_;
    std::uniform_int_distribution<int> distribution_;
};

class vectorLengnthDifferentException : std::exception
{
    public:
    const char * what() const throw ()
    {
        return "vectors passed as arguments must be the same length";
    }
};

class noVariantSpecifiedException : std::exception
{
    public:
    const char * what() const throw ()
    {
        return "A testing variant has to be selected.";
    }
};

class vector_diff
{
    public:
    //sum of errors
    double distance = 0.0;
    //count of errors
    unsigned int boolean_distance = 0;
    //mean squared error
    double mse = 0.0;
 
    std::string to_string()
    {
        return "distance between vectors:\n" + std::to_string(this->distance) + "\n" +
        "boolean distance between vectors:\n" + std::to_string(this->boolean_distance) + "\n" +
        "mse between vectors:\n" + std::to_string(this->mse) +
        "\n";
    }
};

vector_diff vector_distance(const std::vector<int> &v1,const std::vector<int> &v2);

vector_diff vector_boolean_distance(const std::vector<int> &v1,const  std::vector<int> &v2);

vector_diff vector_mse(const std::vector<int> &v1,const  std::vector<int> &v2);

vector_diff vector_statistic_combined(const std::vector<int> &v1,const  std::vector<int> &v2);

vector_diff vector_distance(const std::vector<int> &v1,const std::vector<int> &v2)
{
    if(v1.size() != v2.size())throw vectorLengnthDifferentException();

    unsigned int distance=0;
    for(size_t i=0; i < v1.size(); i++)
    {
        distance+=std::abs(v1[i]-v2[i]);
    }

    vector_diff diff;
    diff.distance = distance;
    return diff;
}

vector_diff vector_boolean_distance(const std::vector<int> &v1,const std::vector<int> &v2)
{
    if(v1.size() != v2.size())throw vectorLengnthDifferentException();

    double boolean_distance=0;
    for(size_t i=0; i < v1.size(); i++)
    {
        if(v1[i]!=v2[i])boolean_distance++;
    }
    boolean_distance/= double(v1.size());

    vector_diff diff;
    diff.boolean_distance = boolean_distance;
    std::cout<<diff.boolean_distance<<std::endl;
    return diff;
}

vector_diff vector_mse(const std::vector<int> &v1,const std::vector<int> &v2)
{
    if(v1.size() != v2.size())throw vectorLengnthDifferentException();

    double mse=0;
    for(size_t i=0; i < v1.size(); i++)
    {
        mse += pow(std::abs(v1[i]-v2[i]),2);
    }
    mse/= double(v1.size());

    vector_diff diff;
    diff.mse = mse;
    return diff;
}

vector_diff vector_statistic_combined(const std::vector<int> &v1,const  std::vector<int> &v2)
{
    vector_diff vd1,vd2,vd3,vd_combined;
    vd1 = vector_distance(v1,v2);
    vd2 = vector_boolean_distance(v1,v2);
    vd3 = vector_mse(v1,v2);

    vd_combined.distance = vd1.distance;
    vd_combined.boolean_distance = vd2.boolean_distance;
    vd_combined.mse = vd3.mse;

    return vd_combined;
}